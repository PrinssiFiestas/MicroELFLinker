# MIT License
# Copyright (c) 2025 Lauri Lorenzo Fiestas
# https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

.intel_syntax noprefix

.global _start

# -----------------------------------------------------------------------------
.section .rodata

foobar_msg:
    .asciz "I am foobar!\n"

# -----------------------------------------------------------------------------
.section .text

_start:
    lea rdi, [bar_msg]
    call bar_puts

    lea rdi, [foobar_msg]
    call bar_puts

    mov rax, 60 # exit(
    mov rdi, 0  #     EXIT_SUCCESS
    syscall     # )
