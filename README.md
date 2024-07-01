# FAST_REG

## Key Features:
- Parallel Processing: Utilizes OpenMP for multithreaded hashing of file chunks.

- SIMD Optimization: Employs AVX intrinsics for vectorized hashing operations.

- Asynchronous I/O: Implements overlapped I/O for efficient file reading.

- Encryption: Incorporates AES-256 for additional cryptographic strength.

- Low Memory Footprint: Uses below 128 MB RAM for 100 GB files (varies with core count).

- High Performance: Outperforms xxHash3 on large files “on my Hardware”.

- Strong Avalanche Effect: Tested on 100 GB files with single-byte modifications.

## Implementation Highlights:
- Chunk Processing: Files are read and hashed in 16 MB chunks using parallel processing.

- AVX Hashing: Custom AVX_hash function leverages SIMD instructions for speed.

- AES Integration: Each chunk undergoes AES encryption as part of the hashing process.

- Final Hash Generation: Combines chunk hashes and applies a substitution cipher for salting.

Performance:
- Processes a 100 GB file in approximately 30 seconds. [NVMe SSD]
- 
- Generates a 256-bit hash.

## Specs:
- Windows 10 and 11 [Win 11 don't run on 7740x, therefore I tested on both]

- i7 7740X and i9 10900X [the SSD is definitely the bottleneck at this point]

- 3400MHz CL12 DDR4 64 GB [but it doesn't matter, my code is designed to use barely any RAM]

- Samsung 980 PRO NVMe M.2 SSD [my hash function benefits extremely from a NVMe]

- Visual Studio 2022

## Conclusion:
This custom C++ file hashing algorithm use advanced techniques like parallel processing, 
SIMD optimization, and asynchronous I/O to achieve high performance on modern hardware 
for very large files (100 GB+). It maintains a low RAM footprint and is tailored for 
NVMe SSDs, to achieve fast hashing speeds. However, performance may degrade on SATA devices, 
especially on HDDs and systems with fewer Core counts. The use of Windows APIs and intrinsics 
may limit portability. Overall, this algorithm showcases the power of optimizing for 
modern hardware to efficiently hash large files.

## Note:
This algorithm is a work in progress and part of my personal C++ learning journey. 
It's not intended for real-world use in its current state. Some aspects may appear 
unoptimized or redundant. As a hobby project, my goal is to explore high-performance 
programming techniques. Feedback is welcome to improve my skills. While the algorithm 
shows promising results, it should be viewed as an educational exercise rather than a 
proper solution to a problem.
