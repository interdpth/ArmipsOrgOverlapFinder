# ArmipsOrgOverlapFinder

**ArmipsOrgOverlapFinder** is a utility for detecting overlapping `.org` memory regions in **Armips** assembly projects. It helps ROM hackers, retro game developers, and embedded engineers catch memory collisions early by analyzing `.asm`, `.s`, and `.inc` files, evaluating symbols, and heuristically resolving `.org` directives.

---

## Features

- Fully compatible with **Armips** syntax.
- Recursively scans multiple directories and follows `.include` directives.
- Builds a symbol table from `NAME equ EXPR`:
  - Supports hex (`$NN`, `0xNN`, `NNh`) and decimal numbers.
- Evaluates simple expressions using `+` and `-` with symbols.
- Parses and resolves `.org` directives numerically, symbolically, or via heuristics.
- Detects overlaps between regions across directories within a configurable tolerance.
- Reports unresolved labels with hints for manual resolution.

---

## Installation

Compile with the C# compiler:

```bash
csc OrgOverlapFinder_advanced.cs