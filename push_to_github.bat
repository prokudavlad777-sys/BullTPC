@echo off
rem Put this file INSIDE the unzipped BullTPC folder (next to CMakeLists.txt) and double-click it.
where git >nul 2>&1 || (echo Git is not installed. Get it at https://git-scm.com/download/win & pause & exit /b)
if not exist CMakeLists.txt (echo Run this file from the BullTPC folder. & pause & exit /b)
git init
git config user.name "r4vex"
git config user.email "prokudavlad777@gmail.com"
git add .
git commit -m "BullTPC: C++ version"
git branch -M main
git remote remove origin >nul 2>&1
git remote add origin https://github.com/prokudavlad777-sys/BullTPC.git
git pull origin main --allow-unrelated-histories --no-edit -X ours
git push -u origin main
echo.
echo Done. Open the Actions tab on GitHub to get BullTPC.exe.
pause
