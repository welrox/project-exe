#pragma once

#define PUSH_ALL_REGS asm("pushq %rax\n" "pushq %rbx\n" "pushq %rcx\n" \
                                 "pushq %rdx\n" "pushq %rdi\n" "pushq %rsi\n")

#define PUSH_ALL_REGS_EXCEPT_RAX asm("pushq %rbx\n" "pushq %rcx\n" \
                                 "pushq %rdx\n" "pushq %rdi\n" "pushq %rsi\n")

#define POP_ALL_REGS asm("popq %rsi\n" "popq %rdi\n" "popq %rdx\n" \
                                 "popq %rcx\n" "popq %rbx\n" "popq %rax\n")

#define POP_ALL_REGS_EXCEPT_RAX asm("popq %rsi\n" "popq %rdi\n" "popq %rdx\n" \
                                 "popq %rcx\n" "popq %rbx\n")