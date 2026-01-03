# Create a simple, valid splash.bmp using PowerShell
$width = 500
$height = 300

# Create a simple bitmap with PowerShell (requires .NET)
Add-Type -AssemblyName System.Drawing

$bitmap = New-Object System.Drawing.Bitmap($width, $height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)

# Fill with blue gradient background
for ($y = 0; $y -lt $height; $y++) {
    for ($x = 0; $x -lt $width; $x++) {
        $blueValue = [int](($y / $height) * 255)
        $color = [System.Drawing.Color]::FromArgb(0, 0, $blueValue)
        $bitmap.SetPixel($x, $y, $color)
    }
}

# Add text
$font = New-Object System.Drawing.Font("Arial", 24, [System.Drawing.FontStyle]::Bold)
$brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
$rect = New-Object System.Drawing.RectangleF(0, 100, $width, 50)
$format = New-Object System.Drawing.StringFormat
$format.Alignment = [System.Drawing.StringAlignment]::Center

$graphics.DrawString("AI Security Monitor", $font, $brush, $rect, $format)
$font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Regular)
$rect = New-Object System.Drawing.RectangleF(0, 160, $width, 30)
$graphics.DrawString("Version 2.0.0 - Portable Edition", $font, $brush, $rect, $format)
$rect = New-Object System.Drawing.RectangleF(0, 200, $width, 30)
$graphics.DrawString("Initializing...", $font, $brush, $rect, $format)

# Save as valid BMP
$bitmap.Save("splash.bmp", [System.Drawing.Imaging.ImageFormat]::Bmp)

$graphics.Dispose()
$bitmap.Dispose()

Write-Host "Created valid splash.bmp" -ForegroundColor Green