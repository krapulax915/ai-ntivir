# AI Models Directory

This directory contains the ONNX models for AI-based threat detection.

## Default Model
- `threat_detection.onnx` - Main threat detection model (not included)

## Usage
Place your trained ONNX models in this directory. The AI engine will automatically load them.

## Model Requirements
- Format: ONNX (.onnx)
- Input: File features (extracted by AI engine)
- Output: Threat score (-1.0 to +1.0)

## Fallback
If no model is found, the system uses heuristic analysis as fallback.
