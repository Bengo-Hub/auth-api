<# 
  Local deployment helper for Auth Service (Windows PowerShell)
  Mirrors auth-service/local-deploy.sh behavior for Windows environments.
#>

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($PSScriptRoot) {
  $ROOT_DIR = $PSScriptRoot
} else {
  $ROOT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
}
Set-Location $ROOT_DIR

$APP_PORT = 4101
$REDIS_CONTAINER_NAME = "learnos-redis"
$SERVICE_IMAGE = "auth-api:local"
$SERVICE_CONTAINER_NAME = "auth-api-local"
$DOCKER_PUSH_TARGET = $env:AUTH_DOCKER_PUSH_TARGET
$ENV_FILE = Join-Path $ROOT_DIR ".env"
$EXAMPLE_ENV = Join-Path $ROOT_DIR "config\example.env"
$KEYS_DIR = Join-Path $ROOT_DIR "config\keys"
$PRIV_KEY = Join-Path $KEYS_DIR "dev_jwt_private.pem"
$PUB_KEY = Join-Path $KEYS_DIR "dev_jwt_public.pem"
$CERTS_DIR = Join-Path $ROOT_DIR "config\certs"

function Log([string] $Message) {
  Write-Host "[local-deploy] $Message"
}

function Require([string] $Cmd) {
  if (-not (Get-Command $Cmd -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $Cmd"
  }
}

function Initialize-EnvFile {
  if (-not (Test-Path -LiteralPath $ENV_FILE)) {
    Log "Creating .env from config/example.env"
    Copy-Item -LiteralPath $EXAMPLE_ENV -Destination $ENV_FILE -Force
  }

  $content = Get-Content -LiteralPath $ENV_FILE -Raw

  if ($content -match "(?m)^AUTH_DB_URL=") {
    $content = [regex]::Replace($content, "(?m)^AUTH_DB_URL=.*", "AUTH_DB_URL=postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable")
  } else {
    $content = $content.TrimEnd() + "`r`nAUTH_DB_URL=postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable`r`n"
  }
  if ($content -match "(?m)^AUTH_TOKEN_PRIVATE_KEY_PATH=") {
    $content = [regex]::Replace($content, "(?m)^AUTH_TOKEN_PRIVATE_KEY_PATH=.*", "AUTH_TOKEN_PRIVATE_KEY_PATH=./config/keys/dev_jwt_private.pem")
  } else {
    $content = $content.TrimEnd() + "`r`nAUTH_TOKEN_PRIVATE_KEY_PATH=./config/keys/dev_jwt_private.pem`r`n"
  }
  if ($content -match "(?m)^AUTH_TOKEN_PUBLIC_KEY_PATH=") {
    $content = [regex]::Replace($content, "(?m)^AUTH_TOKEN_PUBLIC_KEY_PATH=.*", "AUTH_TOKEN_PUBLIC_KEY_PATH=./config/keys/dev_jwt_public.pem")
  } else {
    $content = $content.TrimEnd() + "`r`nAUTH_TOKEN_PUBLIC_KEY_PATH=./config/keys/dev_jwt_public.pem`r`n"
  }

  Set-Content -LiteralPath $ENV_FILE -Value $content -Encoding UTF8
}

function Initialize-KeyMaterial {
  New-Item -ItemType Directory -Path $KEYS_DIR -Force | Out-Null

  if (-not (Test-Path -LiteralPath $PRIV_KEY -PathType Leaf)) {
    Require "openssl"
    Log "Generating JWT private key"
    & openssl genrsa -out $PRIV_KEY 4096 | Out-Null
  }
  if (-not (Test-Path -LiteralPath $PUB_KEY -PathType Leaf)) {
    Require "openssl"
    Log "Deriving JWT public key"
    & openssl rsa -in $PRIV_KEY -pubout -out $PUB_KEY | Out-Null
  }
}

function Test-ContainerExists([string] $Name) {
  $inspect = docker ps -a --filter "name=^${Name}$" --format '{{.ID}}'
  return -not [string]::IsNullOrWhiteSpace($inspect)
}

function Test-ContainerRunning([string] $Name) {
  $inspect = docker ps --filter "name=^${Name}$" --format '{{.ID}}'
  return -not [string]::IsNullOrWhiteSpace($inspect)
}

function Start-RedisDependency {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Log "Docker not found; skipping Redis container. Ensure Redis is reachable at 127.0.0.1:6379."
    return
  }

  $exists = Test-ContainerExists $REDIS_CONTAINER_NAME
  $running = Test-ContainerRunning $REDIS_CONTAINER_NAME

  if (-not $exists) {
    Log "Starting Redis container"
    try {
      docker run -d --name $REDIS_CONTAINER_NAME -p 6379:6379 redis:7 | Out-Null
    } catch {
      Log "Failed to start Redis container (redis:7). Ensure Docker access or run Redis manually: $($_.Exception.Message)"
    }
  } elseif (-not $running) {
    Log "Starting existing Redis container"
    try {
      docker start $REDIS_CONTAINER_NAME | Out-Null
    } catch {
      Log "Failed to start Redis container. Ensure Docker access or run Redis manually: $($_.Exception.Message)"
    }
  } else {
    Log "Redis container already running"
  }
}

function Import-DotenvFile {
  if (-not (Test-Path -LiteralPath $ENV_FILE)) { return }

  foreach ($line in Get-Content -LiteralPath $ENV_FILE) {
    $trimmed = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
    if ($trimmed.StartsWith("#")) { continue }
    $eq = $trimmed.IndexOf("=")
    if ($eq -le 0) { continue }
    $key = $trimmed.Substring(0, $eq).Trim()
    $val = $trimmed.Substring($eq + 1).Trim()
    if ($val.StartsWith('"') -and $val.EndsWith('"')) {
      $val = $val.Substring(1, $val.Length - 2)
    }
    Set-Item -Path "Env:$key" -Value $val
  }
}

function Invoke-DatabaseMigrations {
  if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Log "Go not installed; skipping migrations."
    return
  }
  Log "Running database migrations"
  Import-DotenvFile
  & go run ./cmd/migrate
}

function Invoke-DataSeed {
  if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Log "Go not installed; skipping seed."
    return
  }

  Import-DotenvFile

  $password = $env:SEED_ADMIN_PASSWORD
  if ([string]::IsNullOrWhiteSpace($password)) {
    $password = "ChangeMe123!"
    Log "SEED_ADMIN_PASSWORD not set; using default admin password $password for seeding."
  } else {
    Log "Seeding data with provided admin password."
  }

  $originalPassword = $env:SEED_ADMIN_PASSWORD
  try {
    $env:SEED_ADMIN_PASSWORD = $password
    & go run ./cmd/seed
  } finally {
    if ($originalPassword) {
      $env:SEED_ADMIN_PASSWORD = $originalPassword
    } else {
      Remove-Item Env:SEED_ADMIN_PASSWORD -ErrorAction SilentlyContinue
    }
  }
}

function Invoke-ServiceImageBuild {
  Require "docker"
  Log "Building image $SERVICE_IMAGE"
  docker build -t $SERVICE_IMAGE . --progress=plain| Out-Null
}

function Publish-ServiceImage {
  if ([string]::IsNullOrWhiteSpace($DOCKER_PUSH_TARGET)) {
    Log "AUTH_DOCKER_PUSH_TARGET not set; skipping docker push"
    return
  }
  $targetImage = $DOCKER_PUSH_TARGET
  Log "Pushing image to $targetImage"
  docker tag $SERVICE_IMAGE $targetImage | Out-Null
  docker push $targetImage | Out-Null
}

function New-OverrideEnvVars {
  $overrideArgs = @()
  if (Test-Path -LiteralPath $ENV_FILE) {
    $match = Select-String -Path $ENV_FILE -Pattern '^(?i)AUTH_DB_URL=' -SimpleMatch:$false
    if ($match) {
      $line = if ($match -is [System.Array]) { $match[0].Line } else { $match.Line }
      $dbUrl = ($line -replace '^(?i)AUTH_DB_URL=','')
      if ($dbUrl -match 'localhost|127\.0\.0\.1') {
        $dbUrl = $dbUrl -replace 'localhost','host.docker.internal'
        $dbUrl = $dbUrl -replace '127\.0\.0\.1','host.docker.internal'
        $overrideArgs += @('-e',"AUTH_DB_URL=$dbUrl")
      }
    }
  }
  $overrideArgs += @('-e','AUTH_REDIS_ADDR=host.docker.internal:6379')
  return ,$overrideArgs
}

function Start-ServiceContainerInstance {
  param(
    [switch] $Recreate
  )

  Require "docker"

  if ($Recreate -and (Test-ContainerExists $SERVICE_CONTAINER_NAME)) {
    Log "Removing existing container $SERVICE_CONTAINER_NAME"
    docker rm -f $SERVICE_CONTAINER_NAME | Out-Null
  }

  $overrideArgs = New-OverrideEnvVars
  $keysHostPath = (Resolve-Path -LiteralPath $KEYS_DIR).Path
  $dockerArgs = @(
    'run',
    '-d',
    '--name', $SERVICE_CONTAINER_NAME,
    '-p', "${APP_PORT}:${APP_PORT}",
    '--env-file', $ENV_FILE
  ) + $overrideArgs + @(
    '-v', "${keysHostPath}:/app/config/keys"
  )
  
  # Mount TLS certificates if directory exists and contains cert files
  if (Test-Path -LiteralPath $CERTS_DIR -PathType Container) {
    $certFiles = Get-ChildItem -Path $CERTS_DIR -Filter "*.pem" -ErrorAction SilentlyContinue
    if ($certFiles.Count -gt 0) {
      $certsHostPath = (Resolve-Path -LiteralPath $CERTS_DIR).Path
      $dockerArgs += @('-v', "${certsHostPath}:/app/config/certs")
      Log "Mounting TLS certificates from $certsHostPath"
    }
  }
  
  $dockerArgs += $SERVICE_IMAGE
  Log "Running container $SERVICE_CONTAINER_NAME on :$APP_PORT"
  & docker @dockerArgs | Out-Null
}

function Confirm-ServiceContainer {
  Require "docker"
  $exists = Test-ContainerExists $SERVICE_CONTAINER_NAME
  $running = Test-ContainerRunning $SERVICE_CONTAINER_NAME

  if (-not $exists) {
    Log "Auth service container not found; building image and running new container"
    Invoke-ServiceImageBuild
    Publish-ServiceImage
    Start-ServiceContainerInstance -Recreate
    return
  }

  if (-not $running) {
    Log "Starting existing auth service container"
    docker start $SERVICE_CONTAINER_NAME | Out-Null
  } else {
    Log "Auth service container already running"
  }
}

function Show-Usage {
  @"
Usage: .\local-deploy.ps1 [command]

Commands:
  init         Generate keys and ensure .env exists
  redis        Ensure Redis (Docker) is running
  migrate      Run database migrations
  seed         Seed data (requires SEED_ADMIN_PASSWORD env var)
  up           Init, Redis, migrate, then ensure container is running
  up-docker    Init, Redis, then ensure container is running
  run          Rebuild image and recreate container
  run-docker   Alias for run
  help         Show this help

Examples:
  $env:SEED_ADMIN_PASSWORD = 'ChangeMe123!'; .\local-deploy.ps1 seed
  .\local-deploy.ps1 up
  .\local-deploy.ps1 up-docker
"@ | Write-Host
}

$Command = if ($args.Count -ge 1) { $args[0].ToLowerInvariant() } else { "up" }

switch ($Command) {
  "init" {
    Initialize-EnvFile
    Initialize-KeyMaterial
  }
  "redis" {
    Start-RedisDependency
  }
  "migrate" {
    Initialize-EnvFile
    Invoke-DatabaseMigrations
  }
  "seed" {
    Initialize-EnvFile
    Invoke-DataSeed
  }
  "run" {
    Initialize-EnvFile
    Initialize-KeyMaterial
    Start-RedisDependency
    Invoke-DatabaseMigrations
    Invoke-DataSeed
    Invoke-ServiceImageBuild
    Publish-ServiceImage
    Start-ServiceContainerInstance -Recreate
  }
  "run-docker" {
    Initialize-EnvFile
    Initialize-KeyMaterial
    Start-RedisDependency
    Invoke-DatabaseMigrations
    Invoke-DataSeed
    Invoke-ServiceImageBuild
    Publish-ServiceImage
    Start-ServiceContainerInstance -Recreate
  }
  "up" {
    Initialize-EnvFile
    Initialize-KeyMaterial
    Start-RedisDependency
    Invoke-DatabaseMigrations
    Invoke-DataSeed
    Confirm-ServiceContainer
  }
  "up-docker" {
    Initialize-EnvFile
    Initialize-KeyMaterial
    Start-RedisDependency
    Confirm-ServiceContainer
  }
  "help" { Show-Usage }
  default {
    Show-Usage
    exit 1
  }
}


