# PintOS Virtual Memory Project

---

## 프로젝트 개요

본 프로젝트는 KAIST PintOS를 기반으로 가상 메모리(Virtual Memory) 시스템을 직접 구현하는 운영체제 프로젝트입니다. 
실제 운영체제의 메모리 관리 메커니즘을 코드 레벨에서 이해하고, Paging, Swap, Memory Mapping 등의 핵심 개념을 구현합니다.

### 프로젝트 목표
- 가상 메모리 관리 시스템 구현
- 페이지 폴트 핸들링 및 페이지 교체 정책 구현
- 효율적인 메모리 관리를 통한 시스템 안정성 확보
- 다양한 페이지 타입(Anonymous, File-backed, Uninitialized) 처리

---

## PintOS란?

**PintOS**(Pintos)는 2004년 스탠포드 대학교에서 교육 목적으로 개발된 간단한 운영체제입니다.

### 특징
- x86 아키텍처 기반의 교육용 OS
- 실제 운영체제의 핵심 기능을 학습할 수 있는 최소한의 구조
- Thread, User Program, Virtual Memory, File System 등 4개의 주요 프로젝트로 구성

### KAIST PintOS
본 프로젝트는 스탠포드 PintOS를 기반으로 **KAIST 권영진 교수님** 주도 하에 개선된 **KAIST PintOS**를 사용합니다.

---

## 개발 환경

### 기술 스택
- **OS**: Ubuntu 22.04 LTS
- **Language**: C
- **Architecture**: x86 (32-bit)

---



---

## 테스트 결과

<img width="1512" height="946" alt="스크린샷 2025-10-14 오전 1 30 40" src="https://github.com/user-attachments/assets/5aee40f9-c8b1-46de-aa81-865a7684e51b" />

---

## 추천 학습 자료

- [KAIST PintOS 공식 문서](https://casys-kaist.github.io/pintos-kaist/)
- [OSTEP (Operating Systems: Three Easy Pieces)](https://pages.cs.wisc.edu/~remzi/OSTEP/)
- Computer Systems: A Programmer's Perspective (CSAPP), Chapter 9
- [한양대학교 PintOS 강의 자료](https://velog.io/@shinhojung814/WEEK-11-PintOS-Project-3-Virtual-Memory/)

---

## 라이선스

이 프로젝트는 교육 목적으로 작성되었으며, KAIST PintOS 라이선스를 따릅니다.
