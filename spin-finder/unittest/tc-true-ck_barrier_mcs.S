// TC_OUT thread,0x400b80,0x400b8e,0x0(0x6020a0),0x0(0x6028c0)
barrier_mcs:     file format elf64-x86-64


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
  400788:	push   %rbp
  400789:	push   %rbx
  40078a:	sub    $0x8,%rsp
  40078e:	cmp    $0x2,%edi
  400791:	jle    40093e <main+0x1be>
  400797:	mov    0x8(%rsi),%rdi
  40079b:	mov    %rsi,%rbp
  40079e:	mov    $0xa,%edx
  4007a3:	xor    %esi,%esi
  4007a5:	callq  400720 <strtol@plt>
  4007aa:	test   %eax,%eax
  4007ac:	mov    %rax,%rbx
  4007af:	mov    %eax,0x20210b(%rip)        # 6028c0 <nthr>
  4007b5:	jle    400930 <main+0x1b0>
  4007bb:	movslq %eax,%r12
  4007be:	lea    0x0(,%r12,8),%rdi
  4007c6:	callq  400730 <malloc@plt>
  4007cb:	test   %rax,%rax
  4007ce:	mov    %rax,%r14
  4007d1:	je     400922 <main+0x1a2>
  4007d7:	lea    (%r12,%r12,4),%rdi
  4007db:	shl    $0x4,%rdi
  4007df:	callq  400730 <malloc@plt>
  4007e4:	test   %rax,%rax
  4007e7:	mov    %rax,%r12
  4007ea:	je     400914 <main+0x194>
  4007f0:	mov    %ebx,%esi
  4007f2:	mov    %rax,%rdi
  4007f5:	xor    %ebx,%ebx
  4007f7:	callq  400c20 <ck_barrier_mcs_init>
  4007fc:	mov    0x10(%rbp),%rdi
  400800:	xor    %esi,%esi
  400802:	mov    $0xa,%edx
  400807:	mov    %r14,%rbp
  40080a:	lea    0x2ef(%rip),%r13        # 400b00 <thread>
  400811:	callq  400720 <strtol@plt>
  400816:	mov    0x2017db(%rip),%r15        # 601ff8 <_DYNAMIC+0x1f0>
  40081d:	lea    0x676(%rip),%rdi        # 400e9a <__dso_handle+0x22>
  400824:	mov    $0x1d,%edx
  400829:	mov    $0x1,%esi
  40082e:	mov    %eax,0x202094(%rip)        # 6028c8 <a>
  400834:	mov    (%r15),%rcx
  400837:	callq  400770 <fwrite@plt>
  40083c:	mov    0x20207e(%rip),%edx        # 6028c0 <nthr>
  400842:	test   %edx,%edx
  400844:	jle    400877 <main+0xf7>
  400846:	nopw   %cs:0x0(%rax,%rax,1)
  400850:	xor    %esi,%esi
  400852:	mov    %r12,%rcx
  400855:	mov    %r13,%rdx
  400858:	mov    %rbp,%rdi
  40085b:	callq  4006f0 <pthread_create@plt>
  400860:	test   %eax,%eax
  400862:	jne    400904 <main+0x184>
  400868:	add    $0x1,%ebx
  40086b:	add    $0x8,%rbp
  40086f:	cmp    %ebx,0x20204b(%rip)        # 6028c0 <nthr>
  400875:	jg     400850 <main+0xd0>
  400877:	mov    (%r15),%rcx
  40087a:	lea    0x637(%rip),%rdi        # 400eb8 <__dso_handle+0x40>
  400881:	mov    $0x5,%edx
  400886:	mov    $0x1,%esi
  40088b:	mov    $0x1,%ebx
  400890:	callq  400770 <fwrite@plt>
  400895:	mov    (%r15),%rcx
  400898:	lea    0x701(%rip),%rdi        # 400fa0 <__dso_handle+0x128>
  40089f:	mov    $0x37,%edx
  4008a4:	mov    $0x1,%esi
  4008a9:	callq  400770 <fwrite@plt>
  4008ae:	mov    0x20200c(%rip),%eax        # 6028c0 <nthr>
  4008b4:	test   %eax,%eax
  4008b6:	jle    4008da <main+0x15a>
  4008b8:	nopl   0x0(%rax,%rax,1)
  4008c0:	mov    -0x8(%r14,%rbx,8),%rdi
  4008c5:	xor    %esi,%esi
  4008c7:	callq  400740 <pthread_join@plt>
  4008cc:	mov    %ebx,%eax
  4008ce:	add    $0x1,%rbx
  4008d2:	cmp    %eax,0x201fe8(%rip)        # 6028c0 <nthr>
  4008d8:	jg     4008c0 <main+0x140>
  4008da:	mov    (%r15),%rcx
  4008dd:	lea    0x5da(%rip),%rdi        # 400ebe <__dso_handle+0x46>
  4008e4:	mov    $0xe,%edx
  4008e9:	mov    $0x1,%esi
  4008ee:	callq  400770 <fwrite@plt>
  4008f3:	add    $0x8,%rsp
  4008f7:	xor    %eax,%eax
  4008f9:	pop    %rbx
  4008fa:	pop    %rbp
  4008fb:	pop    %r12
  4008fd:	pop    %r13
  4008ff:	pop    %r14
  400901:	pop    %r15
  400903:	retq   
  400904:	lea    0x6cd(%rip),%rdi        # 400fd8 <__dso_handle+0x160>
  40090b:	mov    %ebx,%esi
  40090d:	xor    %eax,%eax
  40090f:	callq  400a50 <ck_error>
  400914:	lea    0x655(%rip),%rdi        # 400f70 <__dso_handle+0xf8>
  40091b:	xor    %eax,%eax
  40091d:	callq  400a50 <ck_error>
  400922:	lea    0x617(%rip),%rdi        # 400f40 <__dso_handle+0xc8>
  400929:	xor    %eax,%eax
  40092b:	callq  400a50 <ck_error>
  400930:	lea    0x5d1(%rip),%rdi        # 400f08 <__dso_handle+0x90>
  400937:	xor    %eax,%eax
  400939:	callq  400a50 <ck_error>
  40093e:	lea    0x58b(%rip),%rdi        # 400ed0 <__dso_handle+0x58>
  400945:	xor    %eax,%eax
  400947:	callq  400a50 <ck_error>
  40094c:	nopl   0x0(%rax)

0000000000400950 <_start>:
  400950:	xor    %ebp,%ebp
  400952:	mov    %rdx,%r9
  400955:	pop    %rsi
  400956:	mov    %rsp,%rdx
  400959:	and    $0xfffffffffffffff0,%rsp
  40095d:	push   %rax
  40095e:	push   %rsp
  40095f:	mov    $0x400e60,%r8
  400966:	mov    $0x400df0,%rcx
  40096d:	mov    $0x400780,%rdi
  400974:	callq  *0x20166e(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  40097a:	hlt    
  40097b:	nopl   0x0(%rax,%rax,1)

0000000000400980 <deregister_tm_clones>:
  400980:	mov    $0x60206f,%eax
  400985:	push   %rbp
  400986:	sub    $0x602068,%rax
  40098c:	cmp    $0xe,%rax
  400990:	mov    %rsp,%rbp
  400993:	jbe    4009b0 <deregister_tm_clones+0x30>
  400995:	mov    $0x0,%eax
  40099a:	test   %rax,%rax
  40099d:	je     4009b0 <deregister_tm_clones+0x30>
  40099f:	pop    %rbp
  4009a0:	mov    $0x602068,%edi
  4009a5:	jmpq   *%rax
  4009a7:	nopw   0x0(%rax,%rax,1)
  4009b0:	pop    %rbp
  4009b1:	retq   
  4009b2:	nopl   0x0(%rax)
  4009b6:	nopw   %cs:0x0(%rax,%rax,1)

00000000004009c0 <register_tm_clones>:
  4009c0:	mov    $0x602068,%esi
  4009c5:	push   %rbp
  4009c6:	sub    $0x602068,%rsi
  4009cd:	sar    $0x3,%rsi
  4009d1:	mov    %rsp,%rbp
  4009d4:	mov    %rsi,%rax
  4009d7:	shr    $0x3f,%rax
  4009db:	add    %rax,%rsi
  4009de:	sar    %rsi
  4009e1:	je     4009f8 <register_tm_clones+0x38>
  4009e3:	mov    $0x0,%eax
  4009e8:	test   %rax,%rax
  4009eb:	je     4009f8 <register_tm_clones+0x38>
  4009ed:	pop    %rbp
  4009ee:	mov    $0x602068,%edi
  4009f3:	jmpq   *%rax
  4009f5:	nopl   (%rax)
  4009f8:	pop    %rbp
  4009f9:	retq   
  4009fa:	nopw   0x0(%rax,%rax,1)

0000000000400a00 <__do_global_dtors_aux>:
  400a00:	cmpb   $0x0,0x201679(%rip)        # 602080 <completed.6917>
  400a07:	jne    400a1a <__do_global_dtors_aux+0x1a>
  400a09:	push   %rbp
  400a0a:	mov    %rsp,%rbp
  400a0d:	callq  400980 <deregister_tm_clones>
  400a12:	pop    %rbp
  400a13:	movb   $0x1,0x201666(%rip)        # 602080 <completed.6917>
  400a1a:	repz retq 
  400a1c:	nopl   0x0(%rax)

0000000000400a20 <frame_dummy>:
  400a20:	mov    $0x601e00,%edi
  400a25:	cmpq   $0x0,(%rdi)
  400a29:	jne    400a30 <frame_dummy+0x10>
  400a2b:	jmp    4009c0 <register_tm_clones>
  400a2d:	nopl   (%rax)
  400a30:	mov    $0x0,%eax
  400a35:	test   %rax,%rax
  400a38:	je     400a2b <frame_dummy+0xb>
  400a3a:	push   %rbp
  400a3b:	mov    %rsp,%rbp
  400a3e:	callq  *%rax
  400a40:	pop    %rbp
  400a41:	jmpq   4009c0 <register_tm_clones>
  400a46:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a50 <ck_error>:
  400a50:	sub    $0xd8,%rsp
  400a57:	test   %al,%al
  400a59:	mov    %rsi,0x28(%rsp)
  400a5e:	mov    %rdx,0x30(%rsp)
  400a63:	mov    %rcx,0x38(%rsp)
  400a68:	mov    %r8,0x40(%rsp)
  400a6d:	mov    %r9,0x48(%rsp)
  400a72:	je     400aab <ck_error+0x5b>
  400a74:	movaps %xmm0,0x50(%rsp)
  400a79:	movaps %xmm1,0x60(%rsp)
  400a7e:	movaps %xmm2,0x70(%rsp)
  400a83:	movaps %xmm3,0x80(%rsp)
  400a8b:	movaps %xmm4,0x90(%rsp)
  400a93:	movaps %xmm5,0xa0(%rsp)
  400a9b:	movaps %xmm6,0xb0(%rsp)
  400aa3:	movaps %xmm7,0xc0(%rsp)
  400aab:	lea    0xe0(%rsp),%rax
  400ab3:	mov    %rdi,%rsi
  400ab6:	lea    0x8(%rsp),%rdx
  400abb:	mov    %rax,0x10(%rsp)
  400ac0:	lea    0x20(%rsp),%rax
  400ac5:	movl   $0x8,0x8(%rsp)
  400acd:	movl   $0x30,0xc(%rsp)
  400ad5:	mov    %rax,0x18(%rsp)
  400ada:	mov    0x201517(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400ae1:	mov    (%rax),%rdi
  400ae4:	callq  400750 <vfprintf@plt>
  400ae9:	mov    $0x1,%edi
  400aee:	callq  400760 <exit@plt>
  400af3:	nopl   (%rax)
  400af6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b00 <thread>:
  400b00:	push   %r15
  400b02:	push   %r14
  400b04:	push   %r13
  400b06:	push   %r12
  400b08:	push   %rbp
  400b09:	push   %rbx
  400b0a:	mov    %rdi,%rbp
  400b0d:	sub    $0x88,%rsp
  400b14:	mov    0x201dae(%rip),%edx        # 6028c8 <a>
  400b1a:	lock xadd %edx,0x201daa(%rip)        # 6028cc <a+0x4>
  400b22:	xor    %eax,%eax
  400b24:	mov    %rsp,%rdi
  400b27:	mov    $0x10,%ecx
  400b2c:	rep stos %rax,%es:(%rdi)
  400b2f:	and    $0x3,%edx
  400b32:	mov    $0x1,%eax
  400b37:	mov    $0xba,%edi
  400b3c:	mov    %edx,%ecx
  400b3e:	mov    %rsp,%rbx
  400b41:	shl    %cl,%rax
  400b44:	mov    %rax,(%rsp)
  400b48:	xor    %eax,%eax
  400b4a:	callq  400710 <syscall@plt>
  400b4f:	mov    %rsp,%rdx
  400b52:	mov    $0x80,%esi
  400b57:	mov    %eax,%edi
  400b59:	callq  400700 <sched_setaffinity@plt>
  400b5e:	mov    %rsp,%rsi
  400b61:	mov    %rbp,%rdi
  400b64:	callq  400d00 <ck_barrier_mcs_subscribe>
  400b69:	lock incl 0x201530(%rip)        # 6020a0 <barrier_wait>
  400b70:	mov    0x20152a(%rip),%eax        # 6020a0 <barrier_wait>
  400b76:	cmp    %eax,0x201d44(%rip)        # 6028c0 <nthr>
  400b7c:	je     400b90 <thread+0x90>
  400b7e:	xchg   %ax,%ax
  400b80:	pause  
  400b82:	mov    0x201518(%rip),%eax        # 6020a0 <barrier_wait>
  400b88:	cmp    %eax,0x201d32(%rip)        # 6028c0 <nthr>
  400b8e:	jne    400b80 <thread+0x80>
  400b90:	lea    0x201529(%rip),%r12        # 6020c0 <counters>
  400b97:	xor    %r13d,%r13d
  400b9a:	nopw   0x0(%rax,%rax,1)
  400ba0:	mov    %r13d,%r15d
  400ba3:	and    $0x1ff,%r15d
  400baa:	movslq %r15d,%rax
  400bad:	lea    (%r12,%rax,4),%r14
  400bb1:	lock incl (%r14)
  400bb5:	mov    %rbx,%rsi
  400bb8:	mov    %rbp,%rdi
  400bbb:	callq  400d20 <ck_barrier_mcs>
  400bc0:	mov    (%r14),%ecx
  400bc3:	lea    0x1(%r13),%eax
  400bc7:	mov    0x201cf2(%rip),%r8d        # 6028c0 <nthr>
  400bce:	sar    $0x9,%eax
  400bd1:	add    $0x1,%eax
  400bd4:	imul   %r8d,%eax
  400bd8:	cmp    %ecx,%eax
  400bda:	jne    400bfd <thread+0xfd>
  400bdc:	add    $0x2,%r13d
  400be0:	cmp    $0x4c4b40,%r13d
  400be7:	jne    400ba0 <thread+0xa0>
  400be9:	add    $0x88,%rsp
  400bf0:	xor    %eax,%eax
  400bf2:	pop    %rbx
  400bf3:	pop    %rbp
  400bf4:	pop    %r12
  400bf6:	pop    %r13
  400bf8:	pop    %r14
  400bfa:	pop    %r15
  400bfc:	retq   
  400bfd:	lea    0x27c(%rip),%rdi        # 400e80 <__dso_handle+0x8>
  400c04:	mov    %r13d,%edx
  400c07:	mov    %r15d,%esi
  400c0a:	xor    %eax,%eax
  400c0c:	callq  400a50 <ck_error>
  400c11:	nopw   %cs:0x0(%rax,%rax,1)
  400c1b:	nopl   0x0(%rax,%rax,1)

0000000000400c20 <ck_barrier_mcs_init>:
  400c20:	movl   $0x0,(%rdi)
  400c26:	test   %esi,%esi
  400c28:	je     400ce5 <ck_barrier_mcs_init+0xc5>
  400c2e:	push   %rbp
  400c2f:	lea    0x28(%rdi),%r8
  400c33:	push   %rbx
  400c34:	lea    -0x1(%rsi),%ebx
  400c37:	mov    $0x1,%ebp
  400c3c:	mov    $0x2,%r10d
  400c42:	xor    %r9d,%r9d
  400c45:	nopl   (%rax)
  400c48:	lea    0x0(,%r9,4),%edx
  400c50:	lea    -0x10(%r8),%rax
  400c54:	lea    (%r10,%r10,1),%r11d
  400c58:	cmp    %ebx,%edx
  400c5a:	sbb    %ecx,%ecx
  400c5c:	add    $0x1,%edx
  400c5f:	add    $0x4,%rax
  400c63:	mov    %ecx,0x10(%rax)
  400c66:	mov    %ecx,-0x4(%rax)
  400c69:	cmp    %edx,%r11d
  400c6c:	jne    400c58 <ck_barrier_mcs_init+0x38>
  400c6e:	test   %r9d,%r9d
  400c71:	je     400ce7 <ck_barrier_mcs_init+0xc7>
  400c73:	lea    -0x1(%r9),%eax
  400c77:	mov    %eax,%edx
  400c79:	shr    $0x2,%eax
  400c7c:	lea    (%rax,%rax,4),%rax
  400c80:	and    $0x3,%edx
  400c83:	shl    $0x4,%rax
  400c87:	lea    0x18(%rax,%rdx,4),%rax
  400c8c:	add    %rdi,%rax
  400c8f:	cmp    %ebp,%esi
  400c91:	mov    %rax,0x18(%r8)
  400c95:	jbe    400cf1 <ck_barrier_mcs_init+0xd1>
  400c97:	mov    %ebp,%eax
  400c99:	lea    (%rax,%rax,4),%rax
  400c9d:	shl    $0x4,%rax
  400ca1:	lea    0x48(%rdi,%rax,1),%rax
  400ca6:	cmp    %esi,%r10d
  400ca9:	mov    %rax,-0x20(%r8)
  400cad:	jae    400cec <ck_barrier_mcs_init+0xcc>
  400caf:	mov    %r10d,%eax
  400cb2:	lea    (%rax,%rax,4),%rax
  400cb6:	shl    $0x4,%rax
  400cba:	lea    0x48(%rdi,%rax,1),%rax
  400cbf:	add    $0x1,%r9d
  400cc3:	mov    %rax,-0x18(%r8)
  400cc7:	movl   $0x0,0x20(%r8)
  400ccf:	add    $0x2,%r10d
  400cd3:	add    $0x50,%r8
  400cd7:	add    $0x2,%ebp
  400cda:	cmp    %r9d,%esi
  400cdd:	jne    400c48 <ck_barrier_mcs_init+0x28>
  400ce3:	pop    %rbx
  400ce4:	pop    %rbp
  400ce5:	repz retq 
  400ce7:	mov    %r8,%rax
  400cea:	jmp    400c8f <ck_barrier_mcs_init+0x6f>
  400cec:	mov    %r8,%rax
  400cef:	jmp    400cbf <ck_barrier_mcs_init+0x9f>
  400cf1:	mov    %r8,%rax
  400cf4:	jmp    400ca6 <ck_barrier_mcs_init+0x86>
  400cf6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400d00 <ck_barrier_mcs_subscribe>:
  400d00:	movl   $0xffffffff,(%rsi)
  400d06:	mov    $0x1,%eax
  400d0b:	lock xadd %eax,(%rdi)
  400d0f:	mov    %eax,0x4(%rsi)
  400d12:	retq   
  400d13:	nopl   (%rax)
  400d16:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400d20 <ck_barrier_mcs>:
  400d20:	jmp    400d2a <ck_barrier_mcs+0xa>
  400d22:	nopw   0x0(%rax,%rax,1)
  400d28:	pause  
  400d2a:	mov    0x4(%rsi),%eax
  400d2d:	lea    (%rax,%rax,4),%rax
  400d31:	shl    $0x4,%rax
  400d35:	add    %rdi,%rax
  400d38:	mov    0x18(%rax),%edx
  400d3b:	test   %edx,%edx
  400d3d:	jne    400d28 <ck_barrier_mcs+0x8>
  400d3f:	mov    0x1c(%rax),%edx
  400d42:	test   %edx,%edx
  400d44:	jne    400d28 <ck_barrier_mcs+0x8>
  400d46:	mov    0x20(%rax),%edx
  400d49:	test   %edx,%edx
  400d4b:	jne    400d28 <ck_barrier_mcs+0x8>
  400d4d:	mov    0x24(%rax),%eax
  400d50:	test   %eax,%eax
  400d52:	jne    400d28 <ck_barrier_mcs+0x8>
  400d54:	mov    0x4(%rsi),%eax
  400d57:	lea    (%rax,%rax,4),%rax
  400d5b:	shl    $0x4,%rax
  400d5f:	add    %rdi,%rax
  400d62:	mov    0x2c(%rax),%edx
  400d65:	mov    %edx,0x18(%rax)
  400d68:	mov    0x30(%rax),%edx
  400d6b:	mov    %edx,0x1c(%rax)
  400d6e:	mov    0x34(%rax),%edx
  400d71:	mov    %edx,0x20(%rax)
  400d74:	mov    0x38(%rax),%edx
  400d77:	mov    %edx,0x24(%rax)
  400d7a:	mov    0x4(%rsi),%eax
  400d7d:	lea    (%rax,%rax,4),%rax
  400d81:	shl    $0x4,%rax
  400d85:	mov    0x40(%rdi,%rax,1),%rax
  400d8a:	movl   $0x0,(%rax)
  400d90:	mov    0x4(%rsi),%edx
  400d93:	test   %edx,%edx
  400d95:	lea    (%rdx,%rdx,4),%rax
  400d99:	jne    400da9 <ck_barrier_mcs+0x89>
  400d9b:	jmp    400de3 <ck_barrier_mcs+0xc3>
  400d9d:	nopl   (%rax)
  400da0:	pause  
  400da2:	mov    0x4(%rsi),%eax
  400da5:	lea    (%rax,%rax,4),%rax
  400da9:	shl    $0x4,%rax
  400dad:	mov    0x48(%rdi,%rax,1),%edx
  400db1:	mov    (%rsi),%eax
  400db3:	cmp    %edx,%eax
  400db5:	jne    400da0 <ck_barrier_mcs+0x80>
  400db7:	mov    0x4(%rsi),%edx
  400dba:	lea    (%rdx,%rdx,4),%rdx
  400dbe:	shl    $0x4,%rdx
  400dc2:	mov    0x8(%rdi,%rdx,1),%rdx
  400dc7:	mov    %eax,(%rdx)
  400dc9:	mov    0x4(%rsi),%eax
  400dcc:	mov    (%rsi),%edx
  400dce:	lea    (%rax,%rax,4),%rax
  400dd2:	shl    $0x4,%rax
  400dd6:	mov    0x10(%rdi,%rax,1),%rax
  400ddb:	mov    %edx,(%rax)
  400ddd:	notl   (%rsi)
  400ddf:	mfence 
  400de2:	retq   
  400de3:	mov    (%rsi),%eax
  400de5:	jmp    400dba <ck_barrier_mcs+0x9a>
  400de7:	nopw   0x0(%rax,%rax,1)

0000000000400df0 <__libc_csu_init>:
  400df0:	push   %r15
  400df2:	push   %r14
  400df4:	mov    %edi,%r15d
  400df7:	push   %r13
  400df9:	push   %r12
  400dfb:	lea    0x200fee(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400e02:	push   %rbp
  400e03:	lea    0x200fee(%rip),%rbp        # 601df8 <__init_array_end>
  400e0a:	push   %rbx
  400e0b:	mov    %rsi,%r14
  400e0e:	mov    %rdx,%r13
  400e11:	sub    %r12,%rbp
  400e14:	sub    $0x8,%rsp
  400e18:	sar    $0x3,%rbp
  400e1c:	callq  4006c8 <_init>
  400e21:	test   %rbp,%rbp
  400e24:	je     400e46 <__libc_csu_init+0x56>
  400e26:	xor    %ebx,%ebx
  400e28:	nopl   0x0(%rax,%rax,1)
  400e30:	mov    %r13,%rdx
  400e33:	mov    %r14,%rsi
  400e36:	mov    %r15d,%edi
  400e39:	callq  *(%r12,%rbx,8)
  400e3d:	add    $0x1,%rbx
  400e41:	cmp    %rbx,%rbp
  400e44:	jne    400e30 <__libc_csu_init+0x40>
  400e46:	add    $0x8,%rsp
  400e4a:	pop    %rbx
  400e4b:	pop    %rbp
  400e4c:	pop    %r12
  400e4e:	pop    %r13
  400e50:	pop    %r14
  400e52:	pop    %r15
  400e54:	retq   
  400e55:	nop
  400e56:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400e60 <__libc_csu_fini>:
  400e60:	repz retq 

Disassembly of section .fini:

0000000000400e64 <_fini>:
  400e64:	sub    $0x8,%rsp
  400e68:	add    $0x8,%rsp
  400e6c:	retq   
