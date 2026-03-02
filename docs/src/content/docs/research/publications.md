---
title: Publications
description: Academic publications and how to cite SpecMon
---

SpecMon is the result of academic research on bridging formal verification and runtime monitoring. If you use SpecMon in your research, please cite the work below.

## How to cite

If you use SpecMon, please cite the main CCS 2024 paper:

```bibtex
@inproceedings{morio2024specmon,
  author = {Morio, Kevin and Künnemann, Robert},
  title = {SpecMon: Modular Black-Box Runtime Monitoring of Security Protocols},
  year = {2024},
  isbn = {9798400706363},
  publisher = {Association for Computing Machinery},
  address = {New York, NY, USA},
  url = {https://doi.org/10.1145/3658644.3690197},
  doi = {10.1145/3658644.3690197},
  booktitle = {Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security},
  pages = {2741--2755},
  numpages = {15},
  location = {Salt Lake City, UT, USA},
  series = {CCS '24}
}
```

## Publications

### SpecMon: Modular Black-Box Runtime Monitoring of Security Protocols

**Kevin Morio and Robert Künnemann**  
*ACM CCS 2024* — Salt Lake City, UT, USA

The main SpecMon paper introduces the core algorithm for runtime monitoring of security protocols using multiset-rewrite rules. It presents the theoretical foundations, proves soundness and completeness, and demonstrates the approach with a WireGuard case study.

[Paper (ACM DL)](https://dl.acm.org/doi/abs/10.1145/3658644.3690197) · [arXiv](https://arxiv.org/abs/2409.02918) · [Artifact](https://zenodo.org/records/12787864)

---

### SpecMon: Unifying Verification and Monitoring for WireGuard

**Kevin Morio and Robert Künnemann**  
*Runtime Verification Case-Studies Workshop 2025 (RVCase'25)*

This workshop paper focuses on unified models — the approach that enables a single Tamarin specification to work for both formal verification and runtime monitoring. It provides additional details on the WireGuard case study.

[Paper (PDF)](https://seanmk.com/rvcase/RVCase25_paper_3.pdf) · [Workshop](https://seanmk.com/rvcase/) · [Artifact](https://zenodo.org/records/17023428)
