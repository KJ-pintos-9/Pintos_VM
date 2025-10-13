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

## 협업 방식
팀원들은 각자 맡은 기능을 구현해 PR로 공유하고, 데일리 스크럼과 노션을 통해 진행 상황을 꾸준히 업데이트했습니다.
주요 기능은 함께 디버깅하며 페어 프로그래밍으로 완성했고, 때로는 한 컴퓨터에서 협업하며 문제를 해결했습니다.


## ooleem-generator

Anonymous Page / Frame Table 구조 설계 및 anon_page 확장 (is_swapped_out 필드 추가)

Page Fault Handler 및 커널-유저 간 페이지 폴트 처리 로직 구현

Memory Mapping (mmap/munmap) 시스템 설계 및 동기화 로직 개선

spt_kill() 리팩토링을 통해 mmap-exit 테스트 통과

파일 접근 동기화(filesys_lock) 및 메모리 자원 관리 최적화

전체 테스트 케이스 통합 및 디버깅 리드

---

## Yerinnnn

SPT(Supplementary Page Table) 구조 설계 및 주요 함수(spt_init, spt_find, spt_insert) 구현

Frame Table 및 Stack Growth 메커니즘 설계·구현

vm_alloc_page_with_initializer()를 통해 페이지 초기화 과정 정립

프로젝트 전반의 코드 포맷팅, 헤더 구조, include 관계 정리

테스트 케이스 통합 및 디버깅 과정 참여

---

## kimkimkimbo

Lazy Loading 파이프라인 핵심 설계

lazy_load_info 구조체 및 aux 정보 전달 방식 설계

lazy_load_segment() 구현을 통해 유저 프로그램 로딩 과정의 Lazy Allocation 로직 완성

SPT 복사 및 제거 로직 (supplemental_page_table_copy, supplemental_page_table_kill) 구현

테스트 케이스 통합 및 디버깅 과정 참여

---

## 테스트 결과

### 136/141 테스트 케이스 통과 (96.5%)
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
