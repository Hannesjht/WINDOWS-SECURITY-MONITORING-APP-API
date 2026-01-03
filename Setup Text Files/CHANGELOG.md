CHANGELOG.md
markdown

Changelog
v2.0.0 (2025-01-01)

### Added
- New AI security features
- Windows/Linux/Mac support
- File association

### Changed
- Updated to Java 17
- Improved UI

### Fixed
- Security vulnerabilities
- Memory leaks


3. Automated Collection Scripts

Windows Batch Script (`collect-src.bat`):

batch


@echo off
echo Creating source distribution for AI Security v2.0.0
echo ==================================================

REM Create directory structure
mkdir ai-security-2.0.0-src
mkdir ai-security-2.0.0-src\src
mkdir ai-security-2.0.0-src\src\main
mkdir ai-security-2.0.0-src\src\main\java
mkdir ai-security-2.0.0-src\src\main\resources
mkdir ai-security-2.0.0-src\src\test
mkdir ai-security-2.0.0-src\lib
mkdir ai-security-2.0.0-src\docs
mkdir ai-security-2.0.0-src\scripts

REM Copy source files (adjust paths as needed)
echo Copying Java source files...
xcopy /E /I "C:\YourProject\src\*.java" "ai-security-2.0.0-src\src\main\java\"
xcopy /E /I "C:\YourProject\resources\*" "ai-security-2.0.0-src\src\main\resources\"

REM Copy dependencies
echo Copying library dependencies...
if exist "C:\YourProject\lib\*.jar" (
    xcopy "C:\YourProject\lib\*.jar" "ai-security-2.0.0-src\lib\"
)

REM Copy documentation
echo Copying documentation...
copy "README.md" "ai-security-2.0.0-src\"
copy "LICENSE.txt" "ai-security-2.0.0-src\"
copy "CHANGELOG.md" "ai-security-2.0.0-src\"

REM Create build script
echo Creating build scripts...
echo @echo off > "ai-security-2.0.0-src\scripts\build.bat"
echo echo Building AI Security... >> "ai-security-2.0.0-src\scripts\build.bat"
echo javac -cp "..\lib\*" -d ..\bin ..\src\main\java\com\yourcompany\aisecurity\*.java >> "ai-security-2.0.0-src\scripts\build.bat"
echo jar cvfm ..\ai-security-2.0.0.jar ..\MANIFEST.MF -C ..\bin . >> "ai-security-2.0.0-src\scripts\build.bat"

REM Create dependency list
echo Creating dependency manifest...
dir /B "ai-security-2.0.0-src\lib\" > "ai-security-2.0.0-src\lib\DEPENDENCIES.txt"

echo.
echo Source distribution created in: ai-security-2.0.0-src
echo Compress with: tar -czf ai-security-2.0.0-src.tar.gz ai-security-2.0.0-src
pause
```


Linux/Mac Shell Script (`collect-src.sh`):

bash


#!/bin/bash

echo "Creating source distribution for AI Security v2.0.0"
echo "=================================================="

# Create directory structure
mkdir -p ai-security-2.0.0-src/{src/{main/{java,resources},test},lib,docs,scripts,build}

# Copy source files
echo "Copying Java source files..."
find /path/to/your/project -name "*.java" -exec cp --parents {} ai-security-2.0.0-src/src/main/java/ \;

# Copy resources
echo "Copying resources..."
cp -r /path/to/your/project/resources/* ai-security-2.0.0-src/src/main/resources/ 2>/dev/null || true

# Copy dependencies
echo "Copying library dependencies..."
cp /path/to/your/project/lib/*.jar ai-security-2.0.0-src/lib/ 2>/dev/null || true

# Copy documentation
echo "Copying documentation..."
cp README.md LICENSE.txt CHANGELOG.md ai-security-2.0.0-src/

# Create build script
cat > ai-security-2.0.0-src/scripts/build.sh << 'EOF'
#!/bin/bash
echo "Building AI Security..."
javac -cp "../lib/*" -d ../bin $(find ../src/main/java -name "*.java")
jar cvfm ../ai-security-2.0.0.jar ../MANIFEST.MF -C ../bin .
chmod +x ../ai-security-2.0.0.jar
EOF

chmod +x ai-security-2.0.0-src/scripts/build.sh

# Create MANIFEST.MF
cat > ai-security-2.0.0-src/MANIFEST.MF << 'EOF'
Manifest-Version: 1.0
Main-Class: com.yourcompany.aisecurity.Main
Class-Path: lib/*.jar
Created-By: AI Security v2.0.0
EOF

# Create dependency list
ls -la ai-security-2.0.0-src/lib/ > ai-security-2.0.0-src/lib/DEPENDENCIES.txt

echo ""
echo "Source distribution created in: ai-security-2.0.0-src"
echo "Compress with: tar -czf ai-security-2.0.0-src.tar.gz ai-security-2.0.0-src"
```


5. Build Automation Files:

=pom.xml (Maven):

xml


<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.yourcompany</groupId>
    <artifactId>ai-security</artifactId>
    <version>2.0.0</version>
    <packaging>jar</packaging>
    
    <name>AI Security</name>
    <description>AI-powered Security Application</description>
    
    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-jar-plugin</artifactId>
                <version>3.2.0</version>
                <configuration>
                    <archive>
                        <manifest>
                            <mainClass>com.yourcompany.aisecurity.Main</mainClass>
                            <addClasspath>true</addClasspath>
                            <classpathPrefix>lib/</classpathPrefix>
                        </manifest>
                    </archive>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```


build.gradle (Gradle):

groovy


plugins {
    id 'java'
    id 'application'
}

version = '2.0.0'
group = 'com.yourcompany.aisecurity'

sourceCompatibility = '17'
targetCompatibility = '17'

repositories {
    mavenCentral()
}

dependencies {
    // Add your dependencies here
}

application {
    mainClass = 'com.yourcompany.aisecurity.Main'
}

jar {
    manifest {
        attributes(
            'Main-Class': 'com.yourcompany.aisecurity.Main',
            'Class-Path': configurations.runtimeClasspath.files.collect { "lib/$it.name" }.join(' ')
        )
    }
}
```


6. Final Packaging

After organizing your source:

1. Create ZIP/TAR.GZ:

bash

# Windows

powershell Compress-Archive -Path ai-security-2.0.0-src -Destination ai-security-2.0.0-src.zip

# Linux/Mac

tar -czf ai-security-2.0.0-src.tar.gz ai-security-2.0.0-src/


2. Verify includes:
   - [ ] All `.java` source files
   - [ ] Resource files (images, configs)
   - [ ] LICENSE.txt (full GPLv3)
   - [ ] README.md with build instructions
   - [ ] Dependency list
   - [ ] Build scripts
   

3. Update your installer to reference source:

In your script and license agreement, update the source URL:


SOURCE_URL "https://github.com/yourusername/ai-security/releases/v2.0.0/ai-security-2.0.0-src.zip"


7. Quick Start for Your Setup:


Given you already have a working JAR, do this:

1. Extract your JAR to see structure:

bash

jar -xf ai-security-2.0.0.jar


2. Create minimal source package:

bash


mkdir ai-security-2.0.0-src
cp *.java ai-security-2.0.0-src/       # Your source files
cp splash.bmp ai-security-2.0.0-src/
cp filename.ico ai-security-2.0.0-src/
wget -O ai-security-2.0.0-src/LICENSE.txt https://www.gnu.org/licenses/gpl-3.0.txt
# Create README.md as shown above
zip -r ai-security-2.0.0-src.zip ai-security-2.0.0-src

This satisfies GPLv3 requirements!