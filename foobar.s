# MIT License
# Copyright (c) 2025 Lauri Lorenzo Fiestas
# https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

.intel_syntax noprefix

.global _start

# -----------------------------------------------------------------------------
.section .rodata

foobar_pad:
    .ascii "padpad"

foobar_bye:
    .asciz "byebye\n"

foobar_msg:
    .asciz "I am foobar!\n"

# -----------------------------------------------------------------------------
.section .text

say_bye:
    lea rdi, [foobar_bye]
    call bar_puts
    ret

_start:
    lea rdi, [bar_msg]
    call bar_puts

    lea rdi, [foobar_msg]
    call bar_puts

    call say_bye

    mov rax, 60 # exit(
    mov rdi, 0  #     EXIT_SUCCESS
    syscall     # )
