# MIT License
# Copyright (c) 2025 Lauri Lorenzo Fiestas
# https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

.intel_syntax noprefix

.global _start

# -----------------------------------------------------------------------------
.section .rodata

# Henlo would have offset 0 without this, which complicates ELF analysis.
pad:
    .ascii "pad!"

msg:
    .ascii "Henlo\n"
    len = . - msg # sizeof msg

# -----------------------------------------------------------------------------
.section .text

_start:
    mov rax, 1     # write(
    mov rdi, 1     #     stdout_fileno,
    lea rsi, [msg] #     msg,
    mov rdx, len   #     len
    syscall        # )

    mov rax, 60 # exit(
    mov rdi, 0  #     EXIT_SUCCESS
    syscall     # )
