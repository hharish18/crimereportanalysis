# Crime Report Analysis - Setup Script

Write-Host "Setting up Crime Report Analysis Project..." -ForegroundColor Cyan

# check for python
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed or not in PATH."
    exit 1
}

# Create virtual environment
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
} else {
    Write-Host "Virtual environment already exists."
}

# Install dependencies
Write-Host "Installing dependencies..."
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Initialize Database
Write-Host "Initializing database..."
.\.venv\Scripts\python.exe -c "from app import app, db, init_db; app.app_context().push(); init_db();"

Write-Host "Setup complete!" -ForegroundColor Green
Write-Host "To run the application, execute: .\.venv\Scripts\flask run" -ForegroundColor Yellow
