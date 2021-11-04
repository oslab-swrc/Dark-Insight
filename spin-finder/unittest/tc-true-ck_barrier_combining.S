// TC_OUT ck_barrier_combining_aux,0x400d28,0x400d2e,0x0(%rcx)
// TC_OUT ck_barrier_combining_group_init,0x400d90,0x400da9,0x0(%rdx)
// TC_OUT thread,0x400c48,0x400c5f,0x0(0x6020a0),0x0(0x6028c4)
barrier_combining:     file format elf64-x86-64


Disassembly of section .init:

00000000004006c8 <_init>:
  4006c8:	sub    $0x8,%rsp
  4006cc:	mov    0x20191d(%rip),%rax        # 601ff0 <_DYNAMIC+0x1e8>
  4006d3:	test   %rax,%rax
  4006d6:	je     4006da <_init+0x12>
  4006d8:	callq  *%rax
  4006da:	add    $0x8,%rsp
  4006de:	retq   

Disassembly of section .plt:

00000000004006e0 <pthread_create@plt-0x10>:
  4006e0:	pushq  0x201922(%rip)        # 602008 <_GLOBAL_OFFSET_TABLE_+0x8>
  4006e6:	jmpq   *0x201924(%rip)        # 602010 <_GLOBAL_OFFSET_TABLE_+0x10>
  4006ec:	nopl   0x0(%rax)

00000000004006f0 <pthread_create@plt>:
  4006f0:	jmpq   *0x201922(%rip)        # 602018 <_GLOBAL_OFFSET_TABLE_+0x18>
  4006f6:	pushq  $0x0
  4006fb:	jmpq   4006e0 <_init+0x18>

0000000000400700 <sched_setaffinity@plt>:
  400700:	jmpq   *0x20191a(%rip)        # 602020 <_GLOBAL_OFFSET_TABLE_+0x20>
  400706:	pushq  $0x1
  40070b:	jmpq   4006e0 <_init+0x18>

0000000000400710 <syscall@plt>:
  400710:	jmpq   *0x201912(%rip)        # 602028 <_GLOBAL_OFFSET_TABLE_+0x28>
  400716:	pushq  $0x2
  40071b:	jmpq   4006e0 <_init+0x18>

0000000000400720 <strtol@plt>:
  400720:	jmpq   *0x20190a(%rip)        # 602030 <_GLOBAL_OFFSET_TABLE_+0x30>
  400726:	pushq  $0x3
  40072b:	jmpq   4006e0 <_init+0x18>

0000000000400730 <malloc@plt>:
  400730:	jmpq   *0x201902(%rip)        # 602038 <_GLOBAL_OFFSET_TABLE_+0x38>
  400736:	pushq  $0x4
  40073b:	jmpq   4006e0 <_init+0x18>

0000000000400740 <pthread_join@plt>:
  400740:	jmpq   *0x2018fa(%rip)        # 602040 <_GLOBAL_OFFSET_TABLE_+0x40>
  400746:	pushq  $0x5
  40074b:	jmpq   4006e0 <_init+0x18>

0000000000400750 <vfprintf@plt>:
  400750:	jmpq   *0x2018f2(%rip)        # 602048 <_GLOBAL_OFFSET_TABLE_+0x48>
  400756:	pushq  $0x6
  40075b:	jmpq   4006e0 <_init+0x18>

0000000000400760 <exit@plt>:
  400760:	jmpq   *0x2018ea(%rip)        # 602050 <_GLOBAL_OFFSET_TABLE_+0x50>
  400766:	pushq  $0x7
  40076b:	jmpq   4006e0 <_init+0x18>

0000000000400770 <fwrite@plt>:
  400770:	jmpq   *0x2018e2(%rip)        # 602058 <_GLOBAL_OFFSET_TABLE_+0x58>
  400776:	pushq  $0x8
  40077b:	jmpq   4006e0 <_init+0x18>

Disassembly of section .text:

0000000000400780 <main>:
  400780:	push   %r15
  400782:	push   %r14
  400784:	push   %r13
  400786:	push   %r12
  400788:	mov    %rsi,%r13
  40078b:	push   %rbp
  40078c:	push   %rbx
  40078d:	mov    %edi,%ebx
  40078f:	mov    $0x40,%edi
  400794:	sub    $0x8,%rsp
  400798:	callq  400730 <malloc@plt>
  40079d:	test   %rax,%rax
  4007a0:	je     400a05 <main+0x285>
  4007a6:	lea    0x201903(%rip),%rdi        # 6020b0 <barrier>
  4007ad:	mov    %rax,%rsi
  4007b0:	callq  400e40 <ck_barrier_combining_init>
  4007b5:	cmp    $0x3,%ebx
  4007b8:	jle    4009f7 <main+0x277>
  4007be:	mov    0x8(%r13),%rdi
  4007c2:	xor    %esi,%esi
  4007c4:	mov    $0xa,%edx
  4007c9:	callq  400720 <strtol@plt>
  4007ce:	test   %eax,%eax
  4007d0:	mov    %rax,%rbp
  4007d3:	mov    %eax,0x2020e7(%rip)        # 6028c0 <ngroups>
  4007d9:	jle    4009e9 <main+0x269>
  4007df:	mov    0x10(%r13),%rdi
  4007e3:	xor    %esi,%esi
  4007e5:	mov    $0xa,%edx
  4007ea:	callq  400720 <strtol@plt>
  4007ef:	test   %eax,%eax
  4007f1:	mov    %rax,%r12
  4007f4:	mov    %eax,%r14d
  4007f7:	mov    %eax,0x2020c7(%rip)        # 6028c4 <nthr>
  4007fd:	jle    4009db <main+0x25b>
  400803:	movslq %ebp,%rbp
  400806:	mov    %rbp,%rdi
  400809:	shl    $0x6,%rdi
  40080d:	callq  400730 <malloc@plt>
  400812:	test   %rax,%rax
  400815:	mov    %rax,%rbx
  400818:	je     4009cd <main+0x24d>
  40081e:	lea    0x0(,%rbp,8),%rdi
  400826:	movslq %r12d,%rbp
  400829:	imul   %rbp,%rdi
  40082d:	callq  400730 <malloc@plt>
  400832:	test   %rax,%rax
  400835:	mov    %rax,%r12
  400838:	je     4009bf <main+0x23f>
  40083e:	mov    0x18(%r13),%rdi
  400842:	mov    $0xa,%edx
  400847:	xor    %esi,%esi
  400849:	mov    %rbx,%r13
  40084c:	xor    %ebp,%ebp
  40084e:	lea    0x20185b(%rip),%r15        # 6020b0 <barrier>
  400855:	callq  400720 <strtol@plt>
  40085a:	mov    %eax,0x202068(%rip)        # 6028c8 <a>
  400860:	jmp    40086f <main+0xef>
  400862:	nopw   0x0(%rax,%rax,1)
  400868:	mov    0x202055(%rip),%r14d        # 6028c4 <nthr>
  40086f:	mov    %r13,%rsi
  400872:	mov    %r14d,%edx
  400875:	mov    %r15,%rdi
  400878:	callq  400d60 <ck_barrier_combining_group_init>
  40087d:	add    $0x1,%ebp
  400880:	add    $0x40,%r13
  400884:	cmp    %ebp,0x202036(%rip)        # 6028c0 <ngroups>
  40088a:	jg     400868 <main+0xe8>
  40088c:	mov    0x201765(%rip),%r13        # 601ff8 <_DYNAMIC+0x1f0>
  400893:	lea    0x6b0(%rip),%rdi        # 400f4a <__dso_handle+0x22>
  40089a:	mov    $0x1d,%edx
  40089f:	mov    $0x1,%esi
  4008a4:	xor    %r14d,%r14d
  4008a7:	mov    %r12,%r15
  4008aa:	lea    0x31f(%rip),%rbp        # 400bd0 <thread>
  4008b1:	mov    0x0(%r13),%rcx
  4008b5:	callq  400770 <fwrite@plt>
  4008ba:	mov    0x202000(%rip),%ecx        # 6028c0 <ngroups>
  4008c0:	mov    0x201ffe(%rip),%eax        # 6028c4 <nthr>
  4008c6:	imul   %ecx,%eax
  4008c9:	test   %eax,%eax
  4008cb:	jle    400915 <main+0x195>
  4008cd:	nopl   (%rax)
  4008d0:	mov    %r14d,%eax
  4008d3:	xor    %esi,%esi
  4008d5:	mov    %r15,%rdi
  4008d8:	cltd   
  4008d9:	idiv   %ecx
  4008db:	movslq %edx,%rcx
  4008de:	mov    %rcx,%rdx
  4008e1:	shl    $0x6,%rdx
  4008e5:	lea    (%rbx,%rdx,1),%rcx
  4008e9:	mov    %rbp,%rdx
  4008ec:	callq  4006f0 <pthread_create@plt>
  4008f1:	test   %eax,%eax
  4008f3:	jne    4009ae <main+0x22e>
  4008f9:	mov    0x201fc1(%rip),%ecx        # 6028c0 <ngroups>
  4008ff:	mov    0x201fbf(%rip),%eax        # 6028c4 <nthr>
  400905:	add    $0x1,%r14d
  400909:	add    $0x8,%r15
  40090d:	imul   %ecx,%eax
  400910:	cmp    %r14d,%eax
  400913:	jg     4008d0 <main+0x150>
  400915:	mov    0x0(%r13),%rcx
  400919:	lea    0x648(%rip),%rdi        # 400f68 <__dso_handle+0x40>
  400920:	mov    $0x5,%edx
  400925:	mov    $0x1,%esi
  40092a:	mov    $0x1,%ebx
  40092f:	callq  400770 <fwrite@plt>
  400934:	mov    0x0(%r13),%rcx
  400938:	lea    0x791(%rip),%rdi        # 4010d0 <__dso_handle+0x1a8>
  40093f:	mov    $0x37,%edx
  400944:	mov    $0x1,%esi
  400949:	callq  400770 <fwrite@plt>
  40094e:	mov    0x201f70(%rip),%eax        # 6028c4 <nthr>
  400954:	imul   0x201f65(%rip),%eax        # 6028c0 <ngroups>
  40095b:	test   %eax,%eax
  40095d:	jle    400983 <main+0x203>
  40095f:	nop
  400960:	mov    -0x8(%r12,%rbx,8),%rdi
  400965:	xor    %esi,%esi
  400967:	callq  400740 <pthread_join@plt>
  40096c:	mov    0x201f52(%rip),%eax        # 6028c4 <nthr>
  400972:	mov    %ebx,%edx
  400974:	add    $0x1,%rbx
  400978:	imul   0x201f41(%rip),%eax        # 6028c0 <ngroups>
  40097f:	cmp    %edx,%eax
  400981:	jg     400960 <main+0x1e0>
  400983:	mov    0x0(%r13),%rcx
  400987:	lea    0x5e0(%rip),%rdi        # 400f6e <__dso_handle+0x46>
  40098e:	mov    $0xe,%edx
  400993:	mov    $0x1,%esi
  400998:	callq  400770 <fwrite@plt>
  40099d:	add    $0x8,%rsp
  4009a1:	xor    %eax,%eax
  4009a3:	pop    %rbx
  4009a4:	pop    %rbp
  4009a5:	pop    %r12
  4009a7:	pop    %r13
  4009a9:	pop    %r14
  4009ab:	pop    %r15
  4009ad:	retq   
  4009ae:	lea    0x753(%rip),%rdi        # 401108 <__dso_handle+0x1e0>
  4009b5:	mov    %r14d,%esi
  4009b8:	xor    %eax,%eax
  4009ba:	callq  400b20 <ck_error>
  4009bf:	lea    0x6da(%rip),%rdi        # 4010a0 <__dso_handle+0x178>
  4009c6:	xor    %eax,%eax
  4009c8:	callq  400b20 <ck_error>
  4009cd:	lea    0x694(%rip),%rdi        # 401068 <__dso_handle+0x140>
  4009d4:	xor    %eax,%eax
  4009d6:	callq  400b20 <ck_error>
  4009db:	lea    0x64e(%rip),%rdi        # 401030 <__dso_handle+0x108>
  4009e2:	xor    %eax,%eax
  4009e4:	callq  400b20 <ck_error>
  4009e9:	lea    0x610(%rip),%rdi        # 401000 <__dso_handle+0xd8>
  4009f0:	xor    %eax,%eax
  4009f2:	callq  400b20 <ck_error>
  4009f7:	lea    0x5ba(%rip),%rdi        # 400fb8 <__dso_handle+0x90>
  4009fe:	xor    %eax,%eax
  400a00:	callq  400b20 <ck_error>
  400a05:	lea    0x574(%rip),%rdi        # 400f80 <__dso_handle+0x58>
  400a0c:	callq  400b20 <ck_error>
  400a11:	nopw   %cs:0x0(%rax,%rax,1)
  400a1b:	nopl   0x0(%rax,%rax,1)

0000000000400a20 <_start>:
  400a20:	xor    %ebp,%ebp
  400a22:	mov    %rdx,%r9
  400a25:	pop    %rsi
  400a26:	mov    %rsp,%rdx
  400a29:	and    $0xfffffffffffffff0,%rsp
  400a2d:	push   %rax
  400a2e:	push   %rsp
  400a2f:	mov    $0x400f10,%r8
  400a36:	mov    $0x400ea0,%rcx
  400a3d:	mov    $0x400780,%rdi
  400a44:	callq  *0x20159e(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  400a4a:	hlt    
  400a4b:	nopl   0x0(%rax,%rax,1)

0000000000400a50 <deregister_tm_clones>:
  400a50:	mov    $0x60206f,%eax
  400a55:	push   %rbp
  400a56:	sub    $0x602068,%rax
  400a5c:	cmp    $0xe,%rax
  400a60:	mov    %rsp,%rbp
  400a63:	jbe    400a80 <deregister_tm_clones+0x30>
  400a65:	mov    $0x0,%eax
  400a6a:	test   %rax,%rax
  400a6d:	je     400a80 <deregister_tm_clones+0x30>
  400a6f:	pop    %rbp
  400a70:	mov    $0x602068,%edi
  400a75:	jmpq   *%rax
  400a77:	nopw   0x0(%rax,%rax,1)
  400a80:	pop    %rbp
  400a81:	retq   
  400a82:	nopl   0x0(%rax)
  400a86:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a90 <register_tm_clones>:
  400a90:	mov    $0x602068,%esi
  400a95:	push   %rbp
  400a96:	sub    $0x602068,%rsi
  400a9d:	sar    $0x3,%rsi
  400aa1:	mov    %rsp,%rbp
  400aa4:	mov    %rsi,%rax
  400aa7:	shr    $0x3f,%rax
  400aab:	add    %rax,%rsi
  400aae:	sar    %rsi
  400ab1:	je     400ac8 <register_tm_clones+0x38>
  400ab3:	mov    $0x0,%eax
  400ab8:	test   %rax,%rax
  400abb:	je     400ac8 <register_tm_clones+0x38>
  400abd:	pop    %rbp
  400abe:	mov    $0x602068,%edi
  400ac3:	jmpq   *%rax
  400ac5:	nopl   (%rax)
  400ac8:	pop    %rbp
  400ac9:	retq   
  400aca:	nopw   0x0(%rax,%rax,1)

0000000000400ad0 <__do_global_dtors_aux>:
  400ad0:	cmpb   $0x0,0x2015a9(%rip)        # 602080 <completed.6917>
  400ad7:	jne    400aea <__do_global_dtors_aux+0x1a>
  400ad9:	push   %rbp
  400ada:	mov    %rsp,%rbp
  400add:	callq  400a50 <deregister_tm_clones>
  400ae2:	pop    %rbp
  400ae3:	movb   $0x1,0x201596(%rip)        # 602080 <completed.6917>
  400aea:	repz retq 
  400aec:	nopl   0x0(%rax)

0000000000400af0 <frame_dummy>:
  400af0:	mov    $0x601e00,%edi
  400af5:	cmpq   $0x0,(%rdi)
  400af9:	jne    400b00 <frame_dummy+0x10>
  400afb:	jmp    400a90 <register_tm_clones>
  400afd:	nopl   (%rax)
  400b00:	mov    $0x0,%eax
  400b05:	test   %rax,%rax
  400b08:	je     400afb <frame_dummy+0xb>
  400b0a:	push   %rbp
  400b0b:	mov    %rsp,%rbp
  400b0e:	callq  *%rax
  400b10:	pop    %rbp
  400b11:	jmpq   400a90 <register_tm_clones>
  400b16:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b20 <ck_error>:
  400b20:	sub    $0xd8,%rsp
  400b27:	test   %al,%al
  400b29:	mov    %rsi,0x28(%rsp)
  400b2e:	mov    %rdx,0x30(%rsp)
  400b33:	mov    %rcx,0x38(%rsp)
  400b38:	mov    %r8,0x40(%rsp)
  400b3d:	mov    %r9,0x48(%rsp)
  400b42:	je     400b7b <ck_error+0x5b>
  400b44:	movaps %xmm0,0x50(%rsp)
  400b49:	movaps %xmm1,0x60(%rsp)
  400b4e:	movaps %xmm2,0x70(%rsp)
  400b53:	movaps %xmm3,0x80(%rsp)
  400b5b:	movaps %xmm4,0x90(%rsp)
  400b63:	movaps %xmm5,0xa0(%rsp)
  400b6b:	movaps %xmm6,0xb0(%rsp)
  400b73:	movaps %xmm7,0xc0(%rsp)
  400b7b:	lea    0xe0(%rsp),%rax
  400b83:	mov    %rdi,%rsi
  400b86:	lea    0x8(%rsp),%rdx
  400b8b:	mov    %rax,0x10(%rsp)
  400b90:	lea    0x20(%rsp),%rax
  400b95:	movl   $0x8,0x8(%rsp)
  400b9d:	movl   $0x30,0xc(%rsp)
  400ba5:	mov    %rax,0x18(%rsp)
  400baa:	mov    0x201447(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400bb1:	mov    (%rax),%rdi
  400bb4:	callq  400750 <vfprintf@plt>
  400bb9:	mov    $0x1,%edi
  400bbe:	callq  400760 <exit@plt>
  400bc3:	nopl   (%rax)
  400bc6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400bd0 <thread>:
  400bd0:	push   %r15
  400bd2:	push   %r14
  400bd4:	push   %r13
  400bd6:	push   %r12
  400bd8:	push   %rbp
  400bd9:	push   %rbx
  400bda:	sub    $0xa8,%rsp
  400be1:	mov    0x201ce1(%rip),%esi        # 6028c8 <a>
  400be7:	mov    %rdi,0x8(%rsp)
  400bec:	movl   $0xffffffff,0x10(%rsp)
  400bf4:	lock xadd %esi,0x201cd0(%rip)        # 6028cc <a+0x4>
  400bfc:	lea    0x20(%rsp),%rbp
  400c01:	xor    %eax,%eax
  400c03:	mov    $0x10,%ecx
  400c08:	and    $0x3,%esi
  400c0b:	mov    %rbp,%rdi
  400c0e:	rep stos %rax,%es:(%rdi)
  400c11:	mov    %esi,%ecx
  400c13:	mov    $0x1,%eax
  400c18:	mov    $0xba,%edi
  400c1d:	shl    %cl,%rax
  400c20:	mov    %rax,0x20(%rsp)
  400c25:	xor    %eax,%eax
  400c27:	callq  400710 <syscall@plt>
  400c2c:	mov    %rbp,%rdx
  400c2f:	mov    $0x80,%esi
  400c34:	mov    %eax,%edi
  400c36:	callq  400700 <sched_setaffinity@plt>
  400c3b:	lock incl 0x20145e(%rip)        # 6020a0 <barrier_wait>
  400c42:	jmp    400c4a <thread+0x7a>
  400c44:	nopl   0x0(%rax)
  400c48:	pause  
  400c4a:	mov    0x201450(%rip),%edx        # 6020a0 <barrier_wait>
  400c50:	mov    0x201c6e(%rip),%eax        # 6028c4 <nthr>
  400c56:	imul   0x201c63(%rip),%eax        # 6028c0 <ngroups>
  400c5d:	cmp    %edx,%eax
  400c5f:	jne    400c48 <thread+0x78>
  400c61:	lea    0x201458(%rip),%r13        # 6020c0 <counters>
  400c68:	lea    0x10(%rsp),%r12
  400c6d:	lea    0x20143c(%rip),%rbp        # 6020b0 <barrier>
  400c74:	xor    %r14d,%r14d
  400c77:	nopw   0x0(%rax,%rax,1)
  400c80:	mov    %r14d,%r15d
  400c83:	and    $0x1ff,%r15d
  400c8a:	movslq %r15d,%rax
  400c8d:	lea    0x0(%r13,%rax,4),%rbx
  400c92:	lock incl (%rbx)
  400c95:	mov    0x8(%rsp),%rsi
  400c9a:	mov    %r12,%rdx
  400c9d:	mov    %rbp,%rdi
  400ca0:	callq  400e80 <ck_barrier_combining>
  400ca5:	mov    (%rbx),%ecx
  400ca7:	mov    0x201c16(%rip),%r8d        # 6028c4 <nthr>
  400cae:	lea    0x1(%r14),%eax
  400cb2:	imul   0x201c06(%rip),%r8d        # 6028c0 <ngroups>
  400cba:	sar    $0x9,%eax
  400cbd:	add    $0x1,%eax
  400cc0:	imul   %r8d,%eax
  400cc4:	cmp    %ecx,%eax
  400cc6:	jne    400ce9 <thread+0x119>
  400cc8:	add    $0x2,%r14d
  400ccc:	cmp    $0x4c4b40,%r14d
  400cd3:	jne    400c80 <thread+0xb0>
  400cd5:	add    $0xa8,%rsp
  400cdc:	xor    %eax,%eax
  400cde:	pop    %rbx
  400cdf:	pop    %rbp
  400ce0:	pop    %r12
  400ce2:	pop    %r13
  400ce4:	pop    %r14
  400ce6:	pop    %r15
  400ce8:	retq   
  400ce9:	lea    0x240(%rip),%rdi        # 400f30 <__dso_handle+0x8>
  400cf0:	mov    %r14d,%edx
  400cf3:	mov    %r15d,%esi
  400cf6:	xor    %eax,%eax
  400cf8:	callq  400b20 <ck_error>
  400cfd:	nopl   (%rax)

0000000000400d00 <ck_barrier_combining_aux>:
  400d00:	push   %rbx
  400d01:	mov    $0x1,%eax
  400d06:	lock xadd %eax,0x4(%rsi)
  400d0b:	mov    (%rsi),%ebx
  400d0d:	lea    -0x1(%rbx),%ecx
  400d10:	cmp    %eax,%ecx
  400d12:	je     400d38 <ck_barrier_combining_aux+0x38>
  400d14:	mfence 
  400d17:	lea    0x8(%rsi),%rcx
  400d1b:	mov    0x8(%rsi),%eax
  400d1e:	cmp    %eax,%edx
  400d20:	je     400d30 <ck_barrier_combining_aux+0x30>
  400d22:	nopw   0x0(%rax,%rax,1)
  400d28:	pause  
  400d2a:	mov    (%rcx),%eax
  400d2c:	cmp    %eax,%edx
  400d2e:	jne    400d28 <ck_barrier_combining_aux+0x28>
  400d30:	pop    %rbx
  400d31:	retq   
  400d32:	nopw   0x0(%rax,%rax,1)
  400d38:	mov    %rsi,%rbx
  400d3b:	mov    0x10(%rsi),%rsi
  400d3f:	test   %rsi,%rsi
  400d42:	je     400d49 <ck_barrier_combining_aux+0x49>
  400d44:	callq  400d00 <ck_barrier_combining_aux>
  400d49:	movl   $0x0,0x4(%rbx)
  400d50:	mov    0x8(%rbx),%eax
  400d53:	not    %eax
  400d55:	mov    %eax,0x8(%rbx)
  400d58:	pop    %rbx
  400d59:	retq   
  400d5a:	nopw   0x0(%rax,%rax,1)

0000000000400d60 <ck_barrier_combining_group_init>:
  400d60:	mov    %edx,(%rsi)
  400d62:	lea    0x8(%rdi),%rdx
  400d66:	movl   $0x0,0x4(%rsi)
  400d6d:	movl   $0x0,0x8(%rsi)
  400d74:	movq   $0x0,0x20(%rsi)
  400d7c:	mov    $0x1,%ecx
  400d81:	movq   $0x0,0x18(%rsi)
  400d89:	nopl   0x0(%rax)
  400d90:	mov    %ecx,%eax
  400d92:	xchg   %eax,(%rdx)
  400d94:	cmp    $0x1,%eax
  400d97:	jne    400dab <ck_barrier_combining_group_init+0x4b>
  400d99:	nopl   0x0(%rax)
  400da0:	mov    (%rdx),%eax
  400da2:	cmp    $0x1,%eax
  400da5:	jne    400d90 <ck_barrier_combining_group_init+0x30>
  400da7:	pause  
  400da9:	jmp    400da0 <ck_barrier_combining_group_init+0x40>
  400dab:	mov    (%rdi),%rdx
  400dae:	mov    0x18(%rdx),%rax
  400db2:	movq   $0x0,0x28(%rdx)
  400dba:	test   %rax,%rax
  400dbd:	je     400e16 <ck_barrier_combining_group_init+0xb6>
  400dbf:	mov    0x20(%rdx),%rcx
  400dc3:	test   %rcx,%rcx
  400dc6:	je     400e29 <ck_barrier_combining_group_init+0xc9>
  400dc8:	movq   $0x0,0x28(%rax)
  400dd0:	mov    %rax,%rdx
  400dd3:	jmp    400de2 <ck_barrier_combining_group_init+0x82>
  400dd5:	nopl   (%rax)
  400dd8:	mov    %rax,0x28(%rcx)
  400ddc:	mov    %r9,%rdx
  400ddf:	mov    %r8,%rcx
  400de2:	movq   $0x0,0x28(%rcx)
  400dea:	mov    %rcx,0x28(%rax)
  400dee:	mov    0x18(%rdx),%rax
  400df2:	mov    0x28(%rdx),%r9
  400df6:	test   %rax,%rax
  400df9:	je     400e16 <ck_barrier_combining_group_init+0xb6>
  400dfb:	mov    0x20(%rdx),%r8
  400dff:	test   %r8,%r8
  400e02:	je     400e29 <ck_barrier_combining_group_init+0xc9>
  400e04:	test   %r9,%r9
  400e07:	movq   $0x0,0x28(%rax)
  400e0f:	jne    400dd8 <ck_barrier_combining_group_init+0x78>
  400e11:	mov    %rax,%rdx
  400e14:	jmp    400ddf <ck_barrier_combining_group_init+0x7f>
  400e16:	mov    %rsi,0x18(%rdx)
  400e1a:	mov    %rdx,0x10(%rsi)
  400e1e:	addl   $0x1,(%rdx)
  400e21:	movl   $0x0,0x8(%rdi)
  400e28:	retq   
  400e29:	mov    %rsi,0x20(%rdx)
  400e2d:	mov    %rdx,0x10(%rsi)
  400e31:	addl   $0x1,(%rdx)
  400e34:	jmp    400e21 <ck_barrier_combining_group_init+0xc1>
  400e36:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400e40 <ck_barrier_combining_init>:
  400e40:	movl   $0x0,(%rsi)
  400e46:	movl   $0x0,0x4(%rsi)
  400e4d:	movl   $0x0,0x8(%rsi)
  400e54:	movq   $0x0,0x20(%rsi)
  400e5c:	movq   $0x0,0x18(%rsi)
  400e64:	movq   $0x0,0x10(%rsi)
  400e6c:	movl   $0x0,0x8(%rdi)
  400e73:	mov    %rsi,(%rdi)
  400e76:	retq   
  400e77:	nopw   0x0(%rax,%rax,1)

0000000000400e80 <ck_barrier_combining>:
  400e80:	sub    $0x8,%rsp
  400e84:	mov    %rdx,%r8
  400e87:	mov    (%rdx),%edx
  400e89:	callq  400d00 <ck_barrier_combining_aux>
  400e8e:	notl   (%r8)
  400e91:	add    $0x8,%rsp
  400e95:	retq   
  400e96:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400ea0 <__libc_csu_init>:
  400ea0:	push   %r15
  400ea2:	push   %r14
  400ea4:	mov    %edi,%r15d
  400ea7:	push   %r13
  400ea9:	push   %r12
  400eab:	lea    0x200f3e(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400eb2:	push   %rbp
  400eb3:	lea    0x200f3e(%rip),%rbp        # 601df8 <__init_array_end>
  400eba:	push   %rbx
  400ebb:	mov    %rsi,%r14
  400ebe:	mov    %rdx,%r13
  400ec1:	sub    %r12,%rbp
  400ec4:	sub    $0x8,%rsp
  400ec8:	sar    $0x3,%rbp
  400ecc:	callq  4006c8 <_init>
  400ed1:	test   %rbp,%rbp
  400ed4:	je     400ef6 <__libc_csu_init+0x56>
  400ed6:	xor    %ebx,%ebx
  400ed8:	nopl   0x0(%rax,%rax,1)
  400ee0:	mov    %r13,%rdx
  400ee3:	mov    %r14,%rsi
  400ee6:	mov    %r15d,%edi
  400ee9:	callq  *(%r12,%rbx,8)
  400eed:	add    $0x1,%rbx
  400ef1:	cmp    %rbx,%rbp
  400ef4:	jne    400ee0 <__libc_csu_init+0x40>
  400ef6:	add    $0x8,%rsp
  400efa:	pop    %rbx
  400efb:	pop    %rbp
  400efc:	pop    %r12
  400efe:	pop    %r13
  400f00:	pop    %r14
  400f02:	pop    %r15
  400f04:	retq   
  400f05:	nop
  400f06:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400f10 <__libc_csu_fini>:
  400f10:	repz retq 

Disassembly of section .fini:

0000000000400f14 <_fini>:
  400f14:	sub    $0x8,%rsp
  400f18:	add    $0x8,%rsp
  400f1c:	retq   
