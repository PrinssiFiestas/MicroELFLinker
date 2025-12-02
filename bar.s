# MIT License
# Copyright (c) 2025 Lauri Lorenzo Fiestas
# https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

.intel_syntax noprefix

.global bar_puts
.global bar_msg

# -----------------------------------------------------------------------------
.section .rodata

bar_pad9:
    .ascii "padpadpad"

bar_msg:
    .asciz "I am bar!\n"

# -----------------------------------------------------------------------------
.section .text

bar_strlen:
    xor eax, eax
.L0:
    cmp BYTE PTR [rdi + rax], 0
    je .L1
    inc rax
    jmp .L0
.L1:
    ret

bar_puts:
    call bar_strlen
    mov rdx, rax
    mov rsi, rdi
    mov rdi, 1 # STDOUT_FILENO
    mov rax, 1 # write
    syscall
    ret
