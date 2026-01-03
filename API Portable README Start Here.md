
# AI Security Monitor API Portable

## Build Instructions

1. Prerequisites:

   - JDK 17+
   
   - Inno Setup 6+ (for portable installer)

2. Build Application:
   
   
   mvn clean package
   
   # or
   
   ./gradlew build
   
 

Create Portable Installer:

        Open portable.iss in Inno Setup

        Update paths if needed

        Compile to generate AI-Security-Monitor-API-Portable.exe

    Include JRE:

        Download JRE 17+ from Adoptium

        Extract to jre/ folder

        Ensure structure matches the portable configuration
    

 
Follow the text files for setup build and help...