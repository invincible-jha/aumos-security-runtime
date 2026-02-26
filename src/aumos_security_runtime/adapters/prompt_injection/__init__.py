"""Prompt injection detection adapters.

Two complementary detection approaches:
1. pattern_scanner.py — Fast regex-based detection with cached compiled patterns
2. ml_scanner.py — ML-based classification using spaCy for higher accuracy

Both implement IPatternScanner/IMLScanner protocols defined in core/interfaces.py.
"""
