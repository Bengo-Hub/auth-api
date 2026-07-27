package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NodeStat summarizes one node's capacity and live usage (CPU/memory via
// metrics.k8s.io, disk via the kubelet's own stats/summary proxy endpoint —
// no node-exporter/Prometheus required for either).
type NodeStat struct {
	Name         string  `json:"name"`
	Ready        bool    `json:"ready"`
	CPUCapacity  string  `json:"cpu_capacity"`
	CPUUsage     string  `json:"cpu_usage"`
	CPUPercent   float64 `json:"cpu_percent"`
	MemCapacity  string  `json:"mem_capacity"`
	MemUsage     string  `json:"mem_usage"`
	MemPercent   float64 `json:"mem_percent"`
	DiskCapacity string  `json:"disk_capacity"`
	DiskUsage    string  `json:"disk_usage"`
	DiskPercent  float64 `json:"disk_percent"`
}

// PodStat is one row of the top-pods-by-memory table.
type PodStat struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	CPU       string `json:"cpu"`
	Memory    string `json:"memory"`
}

// NamespaceSummary is one namespace's pod count and status.
type NamespaceSummary struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	PodCount int    `json:"pod_count"`
	AgeDays  int    `json:"age_days"`
}

// PVCSummary is one PersistentVolumeClaim's status and requested capacity.
type PVCSummary struct {
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	Capacity     string `json:"capacity"`
	StorageClass string `json:"storage_class"`
}

// IngressSummary is one Ingress's routed hostnames.
type IngressSummary struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Hosts     []string `json:"hosts"`
}

// CronJobStatus reports a CronJob's schedule health — the signal that caught
// two real bugs (auth-session-cleanup wrong-namespace, valhalla-data-refresh
// silently failing every run) during the manual VPS audit this replaces.
type CronJobStatus struct {
	Namespace      string     `json:"namespace"`
	Name           string     `json:"name"`
	Schedule       string     `json:"schedule"`
	Suspended      bool       `json:"suspended"`
	LastScheduled  *time.Time `json:"last_scheduled,omitempty"`
	LastSuccessful *time.Time `json:"last_successful,omitempty"`
	Healthy        bool       `json:"healthy"`
}

// Overview is the full dashboard payload.
type Overview struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Nodes       []NodeStat         `json:"nodes"`
	TopPods     []PodStat          `json:"top_pods"`
	Namespaces  []NamespaceSummary `json:"namespaces"`
	PVCs        []PVCSummary       `json:"pvcs"`
	Ingresses   []IngressSummary   `json:"ingresses"`
	CronJobs    []CronJobStatus    `json:"cronjobs"`
}

const topPodsLimit = 25

// Overview fetches everything the dashboard needs in one pass. Each section
// is best-effort: a failure in one (e.g. metrics-server briefly unavailable)
// does not block the others from rendering.
func (c *Client) Overview(ctx context.Context) (*Overview, error) {
	ov := &Overview{GeneratedAt: time.Now()}

	nodes, err := c.core.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	nodeMetrics := map[string]corev1.ResourceList{}
	if nm, err := c.metrics.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{}); err == nil {
		for _, m := range nm.Items {
			nodeMetrics[m.Name] = m.Usage
		}
	}

	for _, n := range nodes.Items {
		stat := NodeStat{Name: n.Name}
		for _, cond := range n.Status.Conditions {
			if cond.Type == corev1.NodeReady {
				stat.Ready = cond.Status == corev1.ConditionTrue
			}
		}

		cpuCap := n.Status.Allocatable[corev1.ResourceCPU]
		memCap := n.Status.Allocatable[corev1.ResourceMemory]
		stat.CPUCapacity = cpuCap.String()
		stat.MemCapacity = formatBytes(memCap.Value())

		if usage, ok := nodeMetrics[n.Name]; ok {
			cpuUse := usage[corev1.ResourceCPU]
			memUse := usage[corev1.ResourceMemory]
			stat.CPUUsage = cpuUse.String()
			stat.MemUsage = formatBytes(memUse.Value())
			if cpuCap.MilliValue() > 0 {
				stat.CPUPercent = round2(float64(cpuUse.MilliValue()) / float64(cpuCap.MilliValue()) * 100)
			}
			if memCap.Value() > 0 {
				stat.MemPercent = round2(float64(memUse.Value()) / float64(memCap.Value()) * 100)
			}
		}

		if fsCap, fsUsed, ferr := c.nodeDiskUsage(ctx, n.Name); ferr == nil {
			stat.DiskCapacity = formatBytes(fsCap)
			stat.DiskUsage = formatBytes(fsUsed)
			if fsCap > 0 {
				stat.DiskPercent = round2(float64(fsUsed) / float64(fsCap) * 100)
			}
		}

		ov.Nodes = append(ov.Nodes, stat)
	}

	if pm, err := c.metrics.MetricsV1beta1().PodMetricses(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err == nil {
		type ranked struct {
			stat   PodStat
			memVal int64
		}
		var all []ranked
		for _, pod := range pm.Items {
			var cpuTotal, memTotal int64
			for _, ctr := range pod.Containers {
				cpuTotal += ctr.Usage.Cpu().MilliValue()
				memTotal += ctr.Usage.Memory().Value()
			}
			all = append(all, ranked{
				stat: PodStat{
					Namespace: pod.Namespace,
					Name:      pod.Name,
					CPU:       fmt.Sprintf("%dm", cpuTotal),
					Memory:    formatBytes(memTotal),
				},
				memVal: memTotal,
			})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].memVal > all[j].memVal })
		for i, r := range all {
			if i >= topPodsLimit {
				break
			}
			ov.TopPods = append(ov.TopPods, r.stat)
		}
	}

	if pods, err := c.core.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err == nil {
		podCounts := map[string]int{}
		for _, p := range pods.Items {
			podCounts[p.Namespace]++
		}
		if nsList, err := c.core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{}); err == nil {
			for _, ns := range nsList.Items {
				ov.Namespaces = append(ov.Namespaces, NamespaceSummary{
					Name:     ns.Name,
					Status:   string(ns.Status.Phase),
					PodCount: podCounts[ns.Name],
					AgeDays:  int(time.Since(ns.CreationTimestamp.Time).Hours() / 24),
				})
			}
		}
	}

	if pvcs, err := c.core.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err == nil {
		for _, p := range pvcs.Items {
			cap := p.Status.Capacity[corev1.ResourceStorage]
			sc := ""
			if p.Spec.StorageClassName != nil {
				sc = *p.Spec.StorageClassName
			}
			ov.PVCs = append(ov.PVCs, PVCSummary{
				Namespace:    p.Namespace,
				Name:         p.Name,
				Status:       string(p.Status.Phase),
				Capacity:     cap.String(),
				StorageClass: sc,
			})
		}
	}

	if ingresses, err := c.core.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err == nil {
		for _, ing := range ingresses.Items {
			var hosts []string
			for _, rule := range ing.Spec.Rules {
				if rule.Host != "" {
					hosts = append(hosts, rule.Host)
				}
			}
			ov.Ingresses = append(ov.Ingresses, IngressSummary{
				Namespace: ing.Namespace,
				Name:      ing.Name,
				Hosts:     hosts,
			})
		}
	}

	if cronjobs, err := c.core.BatchV1().CronJobs(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err == nil {
		for _, cj := range cronjobs.Items {
			suspended := cj.Spec.Suspend != nil && *cj.Spec.Suspend
			status := CronJobStatus{
				Namespace: cj.Namespace,
				Name:      cj.Name,
				Schedule:  cj.Spec.Schedule,
				Suspended: suspended,
				Healthy:   true,
			}
			if cj.Status.LastScheduleTime != nil {
				t := cj.Status.LastScheduleTime.Time
				status.LastScheduled = &t
			}
			if cj.Status.LastSuccessfulTime != nil {
				t := cj.Status.LastSuccessfulTime.Time
				status.LastSuccessful = &t
			}
			// A CronJob is unhealthy if it has been triggered at least once but
			// never recorded a success at or after that trigger — this is the
			// exact signal that caught the valhalla-data-refresh wget/permission
			// bug (stuck since March despite firing weekly on schedule).
			if !suspended && status.LastScheduled != nil {
				if status.LastSuccessful == nil || status.LastSuccessful.Before(*status.LastScheduled) {
					status.Healthy = false
				}
			}
			ov.CronJobs = append(ov.CronJobs, status)
		}
	}

	return ov, nil
}

// nodeDiskUsage reads the kubelet's built-in Summary API
// (/api/v1/nodes/{name}/proxy/stats/summary) for root filesystem capacity and
// usage. This is the same data node-exporter would have scraped — no extra
// component needed since it's a standard kubelet endpoint, gated here by the
// `nodes/proxy` RBAC verb.
func (c *Client) nodeDiskUsage(ctx context.Context, nodeName string) (capacity int64, used int64, err error) {
	raw, err := c.core.CoreV1().RESTClient().Get().
		Resource("nodes").
		Name(nodeName).
		SubResource("proxy").
		Suffix("stats/summary").
		DoRaw(ctx)
	if err != nil {
		return 0, 0, err
	}

	var summary struct {
		Node struct {
			Fs struct {
				CapacityBytes int64 `json:"capacityBytes"`
				UsedBytes     int64 `json:"usedBytes"`
			} `json:"fs"`
		} `json:"node"`
	}
	if err := json.Unmarshal(raw, &summary); err != nil {
		return 0, 0, err
	}
	return summary.Node.Fs.CapacityBytes, summary.Node.Fs.UsedBytes, nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func round2(f float64) float64 {
	return float64(int(f*100)) / 100
}
