@echo off
title CyberSage AI - Train Machine Learning Model
cd /d "%~dp0"
echo ==============================================================================
echo   CyberSage AI - Machine Learning Model Training Engine
echo   Dataset: 5,000 System Audit Configuration Records
echo   Algorithm: Random Forest Ensemble (100 Decision Trees)
echo ==============================================================================
echo.

python train_model.py

echo.
echo ==============================================================================
echo  Model training complete! Artifacts updated in /models
echo ==============================================================================
echo.
pause
