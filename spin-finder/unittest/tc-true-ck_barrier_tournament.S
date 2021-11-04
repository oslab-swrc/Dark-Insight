// TC_OUT thread,0x400bd0,0x400bde,0x0(0x6020b0),0x0(0x6028c0)
barrier_tournament:     file format elf64-x86-64


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
  400791:	jle    400973 <main+0x1f3>
  400797:	mov    0x8(%rsi),%rdi
  40079b:	mov    %rsi,%rbp
  40079e:	mov    $0xa,%edx
  4007a3:	xor    %esi,%esi
  4007a5:	callq  400720 <strtol@plt>
  4007aa:	test   %eax,%eax
  4007ac:	mov    %rax,%rbx
  4007af:	mov    %eax,0x20210b(%rip)        # 6028c0 <nthr>
  4007b5:	jle    40098f <main+0x20f>
  4007bb:	mov    0x10(%rbp),%rdi
  4007bf:	movslq %ebx,%rbp
  4007c2:	xor    %esi,%esi
  4007c4:	mov    $0xa,%edx
  4007c9:	shl    $0x3,%rbp
  4007cd:	callq  400720 <strtol@plt>
  4007d2:	mov    %rbp,%rdi
  4007d5:	mov    %eax,0x2020ed(%rip)        # 6028c8 <a>
  4007db:	callq  400730 <malloc@plt>
  4007e0:	test   %rax,%rax
  4007e3:	mov    %rax,%r13
  4007e6:	je     400981 <main+0x201>
  4007ec:	mov    %rbp,%rdi
  4007ef:	callq  400730 <malloc@plt>
  4007f4:	test   %rax,%rax
  4007f7:	mov    %rax,%r14
  4007fa:	je     400955 <main+0x1d5>
  400800:	mov    %ebx,%edi
  400802:	callq  400cb0 <ck_barrier_tournament_size>
  400807:	mov    0x2020b2(%rip),%r15d        # 6028c0 <nthr>
  40080e:	test   %r15d,%r15d
  400811:	jle    40084d <main+0xcd>
  400813:	mov    %eax,%eax
  400815:	mov    %r14,%rbx
  400818:	lea    (%rax,%rax,2),%rbp
  40081c:	lea    -0x1(%r15),%eax
  400820:	lea    0x8(%r14,%rax,8),%r12
  400825:	shl    $0x3,%rbp
  400829:	nopl   0x0(%rax)
  400830:	mov    %rbp,%rdi
  400833:	callq  400730 <malloc@plt>
  400838:	test   %rax,%rax
  40083b:	mov    %rax,(%rbx)
  40083e:	je     400955 <main+0x1d5>
  400844:	add    $0x8,%rbx
  400848:	cmp    %r12,%rbx
  40084b:	jne    400830 <main+0xb0>
  40084d:	lea    0x20184c(%rip),%rdi        # 6020a0 <barrier>
  400854:	mov    %r14,%rsi
  400857:	mov    %r15d,%edx
  40085a:	xor    %ebx,%ebx
  40085c:	mov    %r13,%rbp
  40085f:	lea    0x2ea(%rip),%r14        # 400b50 <thread>
  400866:	callq  400d30 <ck_barrier_tournament_init>
  40086b:	mov    0x201786(%rip),%r12        # 601ff8 <_DYNAMIC+0x1f0>
  400872:	lea    0x811(%rip),%rdi        # 40108a <__dso_handle+0x22>
  400879:	mov    $0x1d,%edx
  40087e:	mov    $0x1,%esi
  400883:	mov    (%r12),%rcx
  400887:	callq  400770 <fwrite@plt>
  40088c:	mov    0x20202e(%rip),%edx        # 6028c0 <nthr>
  400892:	test   %edx,%edx
  400894:	jle    4008c6 <main+0x146>
  400896:	nopw   %cs:0x0(%rax,%rax,1)
  4008a0:	xor    %ecx,%ecx
  4008a2:	xor    %esi,%esi
  4008a4:	mov    %r14,%rdx
  4008a7:	mov    %rbp,%rdi
  4008aa:	callq  4006f0 <pthread_create@plt>
  4008af:	test   %eax,%eax
  4008b1:	jne    400963 <main+0x1e3>
  4008b7:	add    $0x1,%ebx
  4008ba:	add    $0x8,%rbp
  4008be:	cmp    %ebx,0x201ffc(%rip)        # 6028c0 <nthr>
  4008c4:	jg     4008a0 <main+0x120>
  4008c6:	mov    (%r12),%rcx
  4008ca:	lea    0x7d7(%rip),%rdi        # 4010a8 <__dso_handle+0x40>
  4008d1:	mov    $0x5,%edx
  4008d6:	mov    $0x1,%esi
  4008db:	mov    $0x1,%ebx
  4008e0:	callq  400770 <fwrite@plt>
  4008e5:	mov    (%r12),%rcx
  4008e9:	lea    0x8a0(%rip),%rdi        # 401190 <__dso_handle+0x128>
  4008f0:	mov    $0x37,%edx
  4008f5:	mov    $0x1,%esi
  4008fa:	callq  400770 <fwrite@plt>
  4008ff:	mov    0x201fbb(%rip),%eax        # 6028c0 <nthr>
  400905:	test   %eax,%eax
  400907:	jle    40092a <main+0x1aa>
  400909:	nopl   0x0(%rax)
  400910:	mov    -0x8(%r13,%rbx,8),%rdi
  400915:	xor    %esi,%esi
  400917:	callq  400740 <pthread_join@plt>
  40091c:	mov    %ebx,%eax
  40091e:	add    $0x1,%rbx
  400922:	cmp    %eax,0x201f98(%rip)        # 6028c0 <nthr>
  400928:	jg     400910 <main+0x190>
  40092a:	mov    (%r12),%rcx
  40092e:	lea    0x779(%rip),%rdi        # 4010ae <__dso_handle+0x46>
  400935:	mov    $0xe,%edx
  40093a:	mov    $0x1,%esi
  40093f:	callq  400770 <fwrite@plt>
  400944:	add    $0x8,%rsp
  400948:	xor    %eax,%eax
  40094a:	pop    %rbx
  40094b:	pop    %rbp
  40094c:	pop    %r12
  40094e:	pop    %r13
  400950:	pop    %r14
  400952:	pop    %r15
  400954:	retq   
  400955:	lea    0x804(%rip),%rdi        # 401160 <__dso_handle+0xf8>
  40095c:	xor    %eax,%eax
  40095e:	callq  400aa0 <ck_error>
  400963:	lea    0x85e(%rip),%rdi        # 4011c8 <__dso_handle+0x160>
  40096a:	mov    %ebx,%esi
  40096c:	xor    %eax,%eax
  40096e:	callq  400aa0 <ck_error>
  400973:	lea    0x746(%rip),%rdi        # 4010c0 <__dso_handle+0x58>
  40097a:	xor    %eax,%eax
  40097c:	callq  400aa0 <ck_error>
  400981:	lea    0x7a8(%rip),%rdi        # 401130 <__dso_handle+0xc8>
  400988:	xor    %eax,%eax
  40098a:	callq  400aa0 <ck_error>
  40098f:	lea    0x762(%rip),%rdi        # 4010f8 <__dso_handle+0x90>
  400996:	xor    %eax,%eax
  400998:	callq  400aa0 <ck_error>
  40099d:	nopl   (%rax)

00000000004009a0 <_start>:
  4009a0:	xor    %ebp,%ebp
  4009a2:	mov    %rdx,%r9
  4009a5:	pop    %rsi
  4009a6:	mov    %rsp,%rdx
  4009a9:	and    $0xfffffffffffffff0,%rsp
  4009ad:	push   %rax
  4009ae:	push   %rsp
  4009af:	mov    $0x401050,%r8
  4009b6:	mov    $0x400fe0,%rcx
  4009bd:	mov    $0x400780,%rdi
  4009c4:	callq  *0x20161e(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  4009ca:	hlt    
  4009cb:	nopl   0x0(%rax,%rax,1)

00000000004009d0 <deregister_tm_clones>:
  4009d0:	mov    $0x60206f,%eax
  4009d5:	push   %rbp
  4009d6:	sub    $0x602068,%rax
  4009dc:	cmp    $0xe,%rax
  4009e0:	mov    %rsp,%rbp
  4009e3:	jbe    400a00 <deregister_tm_clones+0x30>
  4009e5:	mov    $0x0,%eax
  4009ea:	test   %rax,%rax
  4009ed:	je     400a00 <deregister_tm_clones+0x30>
  4009ef:	pop    %rbp
  4009f0:	mov    $0x602068,%edi
  4009f5:	jmpq   *%rax
  4009f7:	nopw   0x0(%rax,%rax,1)
  400a00:	pop    %rbp
  400a01:	retq   
  400a02:	nopl   0x0(%rax)
  400a06:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a10 <register_tm_clones>:
  400a10:	mov    $0x602068,%esi
  400a15:	push   %rbp
  400a16:	sub    $0x602068,%rsi
  400a1d:	sar    $0x3,%rsi
  400a21:	mov    %rsp,%rbp
  400a24:	mov    %rsi,%rax
  400a27:	shr    $0x3f,%rax
  400a2b:	add    %rax,%rsi
  400a2e:	sar    %rsi
  400a31:	je     400a48 <register_tm_clones+0x38>
  400a33:	mov    $0x0,%eax
  400a38:	test   %rax,%rax
  400a3b:	je     400a48 <register_tm_clones+0x38>
  400a3d:	pop    %rbp
  400a3e:	mov    $0x602068,%edi
  400a43:	jmpq   *%rax
  400a45:	nopl   (%rax)
  400a48:	pop    %rbp
  400a49:	retq   
  400a4a:	nopw   0x0(%rax,%rax,1)

0000000000400a50 <__do_global_dtors_aux>:
  400a50:	cmpb   $0x0,0x201629(%rip)        # 602080 <completed.6917>
  400a57:	jne    400a6a <__do_global_dtors_aux+0x1a>
  400a59:	push   %rbp
  400a5a:	mov    %rsp,%rbp
  400a5d:	callq  4009d0 <deregister_tm_clones>
  400a62:	pop    %rbp
  400a63:	movb   $0x1,0x201616(%rip)        # 602080 <completed.6917>
  400a6a:	repz retq 
  400a6c:	nopl   0x0(%rax)

0000000000400a70 <frame_dummy>:
  400a70:	mov    $0x601e00,%edi
  400a75:	cmpq   $0x0,(%rdi)
  400a79:	jne    400a80 <frame_dummy+0x10>
  400a7b:	jmp    400a10 <register_tm_clones>
  400a7d:	nopl   (%rax)
  400a80:	mov    $0x0,%eax
  400a85:	test   %rax,%rax
  400a88:	je     400a7b <frame_dummy+0xb>
  400a8a:	push   %rbp
  400a8b:	mov    %rsp,%rbp
  400a8e:	callq  *%rax
  400a90:	pop    %rbp
  400a91:	jmpq   400a10 <register_tm_clones>
  400a96:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400aa0 <ck_error>:
  400aa0:	sub    $0xd8,%rsp
  400aa7:	test   %al,%al
  400aa9:	mov    %rsi,0x28(%rsp)
  400aae:	mov    %rdx,0x30(%rsp)
  400ab3:	mov    %rcx,0x38(%rsp)
  400ab8:	mov    %r8,0x40(%rsp)
  400abd:	mov    %r9,0x48(%rsp)
  400ac2:	je     400afb <ck_error+0x5b>
  400ac4:	movaps %xmm0,0x50(%rsp)
  400ac9:	movaps %xmm1,0x60(%rsp)
  400ace:	movaps %xmm2,0x70(%rsp)
  400ad3:	movaps %xmm3,0x80(%rsp)
  400adb:	movaps %xmm4,0x90(%rsp)
  400ae3:	movaps %xmm5,0xa0(%rsp)
  400aeb:	movaps %xmm6,0xb0(%rsp)
  400af3:	movaps %xmm7,0xc0(%rsp)
  400afb:	lea    0xe0(%rsp),%rax
  400b03:	mov    %rdi,%rsi
  400b06:	lea    0x8(%rsp),%rdx
  400b0b:	mov    %rax,0x10(%rsp)
  400b10:	lea    0x20(%rsp),%rax
  400b15:	movl   $0x8,0x8(%rsp)
  400b1d:	movl   $0x30,0xc(%rsp)
  400b25:	mov    %rax,0x18(%rsp)
  400b2a:	mov    0x2014c7(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400b31:	mov    (%rax),%rdi
  400b34:	callq  400750 <vfprintf@plt>
  400b39:	mov    $0x1,%edi
  400b3e:	callq  400760 <exit@plt>
  400b43:	nopl   (%rax)
  400b46:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b50 <thread>:
  400b50:	push   %r15
  400b52:	push   %r14
  400b54:	push   %r13
  400b56:	push   %r12
  400b58:	push   %rbp
  400b59:	push   %rbx
  400b5a:	sub    $0x88,%rsp
  400b61:	mov    0x201d61(%rip),%edx        # 6028c8 <a>
  400b67:	lock xadd %edx,0x201d5d(%rip)        # 6028cc <a+0x4>
  400b6f:	xor    %eax,%eax
  400b71:	mov    %rsp,%rdi
  400b74:	mov    $0x10,%ecx
  400b79:	rep stos %rax,%es:(%rdi)
  400b7c:	and    $0x3,%edx
  400b7f:	mov    $0x1,%eax
  400b84:	mov    $0xba,%edi
  400b89:	mov    %edx,%ecx
  400b8b:	mov    %rsp,%rbx
  400b8e:	shl    %cl,%rax
  400b91:	mov    %rax,(%rsp)
  400b95:	xor    %eax,%eax
  400b97:	callq  400710 <syscall@plt>
  400b9c:	mov    %rsp,%rdx
  400b9f:	mov    $0x80,%esi
  400ba4:	mov    %eax,%edi
  400ba6:	callq  400700 <sched_setaffinity@plt>
  400bab:	lea    0x2014ee(%rip),%rdi        # 6020a0 <barrier>
  400bb2:	mov    %rsp,%rsi
  400bb5:	callq  400c90 <ck_barrier_tournament_subscribe>
  400bba:	lock incl 0x2014ef(%rip)        # 6020b0 <barrier_wait>
  400bc1:	mov    0x2014e9(%rip),%eax        # 6020b0 <barrier_wait>
  400bc7:	cmp    %eax,0x201cf3(%rip)        # 6028c0 <nthr>
  400bcd:	je     400be0 <thread+0x90>
  400bcf:	nop
  400bd0:	pause  
  400bd2:	mov    0x2014d8(%rip),%eax        # 6020b0 <barrier_wait>
  400bd8:	cmp    %eax,0x201ce2(%rip)        # 6028c0 <nthr>
  400bde:	jne    400bd0 <thread+0x80>
  400be0:	lea    0x2014d9(%rip),%r12        # 6020c0 <counters>
  400be7:	lea    0x2014b2(%rip),%rbp        # 6020a0 <barrier>
  400bee:	xor    %r13d,%r13d
  400bf1:	nopl   0x0(%rax)
  400bf8:	mov    %r13d,%r15d
  400bfb:	and    $0x1ff,%r15d
  400c02:	movslq %r15d,%rax
  400c05:	lea    (%r12,%rax,4),%r14
  400c09:	lock incl (%r14)
  400c0d:	mov    %rbx,%rsi
  400c10:	mov    %rbp,%rdi
  400c13:	callq  400ea0 <ck_barrier_tournament>
  400c18:	mov    (%r14),%ecx
  400c1b:	lea    0x1(%r13),%eax
  400c1f:	mov    0x201c9a(%rip),%r8d        # 6028c0 <nthr>
  400c26:	sar    $0x9,%eax
  400c29:	add    $0x1,%eax
  400c2c:	imul   %r8d,%eax
  400c30:	cmp    %ecx,%eax
  400c32:	jne    400c78 <thread+0x128>
  400c34:	add    $0x2,%r13d
  400c38:	cmp    $0x4c4b40,%r13d
  400c3f:	jne    400bf8 <thread+0xa8>
  400c41:	lock incl 0x201468(%rip)        # 6020b0 <barrier_wait>
  400c48:	jmp    400c52 <thread+0x102>
  400c4a:	nopw   0x0(%rax,%rax,1)
  400c50:	pause  
  400c52:	mov    0x201458(%rip),%edx        # 6020b0 <barrier_wait>
  400c58:	mov    0x201c62(%rip),%eax        # 6028c0 <nthr>
  400c5e:	add    %eax,%eax
  400c60:	cmp    %eax,%edx
  400c62:	jne    400c50 <thread+0x100>
  400c64:	add    $0x88,%rsp
  400c6b:	xor    %eax,%eax
  400c6d:	pop    %rbx
  400c6e:	pop    %rbp
  400c6f:	pop    %r12
  400c71:	pop    %r13
  400c73:	pop    %r14
  400c75:	pop    %r15
  400c77:	retq   
  400c78:	lea    0x3f1(%rip),%rdi        # 401070 <__dso_handle+0x8>
  400c7f:	mov    %r13d,%edx
  400c82:	mov    %r15d,%esi
  400c85:	xor    %eax,%eax
  400c87:	callq  400aa0 <ck_error>
  400c8c:	nopl   0x0(%rax)

0000000000400c90 <ck_barrier_tournament_subscribe>:
  400c90:	movl   $0xffffffff,(%rsi)
  400c96:	mov    $0x1,%eax
  400c9b:	lock xadd %eax,(%rdi)
  400c9f:	mov    %eax,0x4(%rsi)
  400ca2:	retq   
  400ca3:	nopl   (%rax)
  400ca6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400cb0 <ck_barrier_tournament_size>:
  400cb0:	sub    $0x1,%edi
  400cb3:	mov    $0x10,%esi
  400cb8:	mov    %edi,%edx
  400cba:	shr    %edx
  400cbc:	or     %edi,%edx
  400cbe:	mov    %edx,%edi
  400cc0:	shr    $0x2,%edi
  400cc3:	or     %edi,%edx
  400cc5:	mov    %edx,%edi
  400cc7:	shr    $0x4,%edi
  400cca:	or     %edi,%edx
  400ccc:	mov    %edx,%eax
  400cce:	shr    $0x8,%eax
  400cd1:	or     %eax,%edx
  400cd3:	mov    %edx,%eax
  400cd5:	shr    $0x10,%eax
  400cd8:	or     %eax,%edx
  400cda:	xor    %eax,%eax
  400cdc:	add    $0x1,%edx
  400cdf:	test   $0xaaaaaaaa,%edx
  400ce5:	mov    %edx,%ecx
  400ce7:	setne  %al
  400cea:	and    $0xffff0000,%ecx
  400cf0:	cmovne %esi,%ecx
  400cf3:	mov    $0x8,%esi
  400cf8:	or     %ecx,%eax
  400cfa:	mov    %edx,%ecx
  400cfc:	and    $0xff00ff00,%ecx
  400d02:	cmovne %esi,%ecx
  400d05:	mov    $0x4,%esi
  400d0a:	or     %ecx,%eax
  400d0c:	mov    %edx,%ecx
  400d0e:	and    $0xf0f0f0f0,%ecx
  400d14:	cmovne %esi,%ecx
  400d17:	or     %ecx,%eax
  400d19:	and    $0xcccccccc,%edx
  400d1f:	mov    $0x2,%ecx
  400d24:	cmovne %ecx,%edx
  400d27:	or     %eax,%edx
  400d29:	lea    0x1(%rdx),%eax
  400d2c:	retq   
  400d2d:	nopl   (%rax)

0000000000400d30 <ck_barrier_tournament_init>:
  400d30:	push   %r15
  400d32:	push   %r14
  400d34:	mov    %rsi,%r14
  400d37:	push   %r13
  400d39:	push   %r12
  400d3b:	push   %rbp
  400d3c:	push   %rbx
  400d3d:	mov    %edx,%ebp
  400d3f:	mov    %rdi,%rbx
  400d42:	sub    $0x18,%rsp
  400d46:	mov    %rdi,0x8(%rsp)
  400d4b:	movl   $0x0,(%rdi)
  400d51:	mov    %edx,%edi
  400d53:	callq  400cb0 <ck_barrier_tournament_size>
  400d58:	test   %ebp,%ebp
  400d5a:	mov    %eax,0x4(%rbx)
  400d5d:	je     400e4d <ck_barrier_tournament_init+0x11d>
  400d63:	lea    -0x2(%rax),%edx
  400d66:	xor    %esi,%esi
  400d68:	lea    (%rdx,%rdx,2),%rdx
  400d6c:	lea    0x30(,%rdx,8),%r15
  400d74:	nopl   0x0(%rax)
  400d78:	mov    (%r14,%rsi,8),%r10
  400d7c:	cmp    $0x1,%eax
  400d7f:	mov    %esi,%r9d
  400d82:	movl   $0x0,0x10(%r10)
  400d8a:	movl   $0x2,(%r10)
  400d91:	jbe    400e41 <ck_barrier_tournament_init+0x111>
  400d97:	lea    0x18(%r10),%rdx
  400d9b:	lea    (%r10,%r15,1),%r11
  400d9f:	mov    $0x1,%ebx
  400da4:	mov    $0x2,%ecx
  400da9:	jmp    400de7 <ck_barrier_tournament_init+0xb7>
  400dab:	nopl   0x0(%rax,%rax,1)
  400db0:	test   %r9d,%r9d
  400db3:	jne    400e78 <ck_barrier_tournament_init+0x148>
  400db9:	cmp    %ecx,%ebp
  400dbb:	ja     400e78 <ck_barrier_tournament_init+0x148>
  400dc1:	movl   $0x1,(%rdx)
  400dc7:	lea    (%r9,%rbx,1),%edi
  400dcb:	add    (%r14,%rdi,8),%r8
  400dcf:	add    $0x10,%r8
  400dd3:	mov    %r8,0x8(%rdx)
  400dd7:	add    $0x18,%rdx
  400ddb:	lea    (%rcx,%rcx,1),%edi
  400dde:	mov    %ecx,%ebx
  400de0:	cmp    %rdx,%r11
  400de3:	je     400e41 <ck_barrier_tournament_init+0x111>
  400de5:	mov    %edi,%ecx
  400de7:	lea    -0x1(%rcx),%edi
  400dea:	mov    %rdx,%r8
  400ded:	movl   $0x0,0x10(%rdx)
  400df4:	sub    %r10,%r8
  400df7:	and    %r9d,%edi
  400dfa:	jne    400e18 <ck_barrier_tournament_init+0xe8>
  400dfc:	lea    (%r9,%rbx,1),%r12d
  400e00:	mov    %ecx,%r13d
  400e03:	cmp    %ecx,%r12d
  400e06:	cmovae %r12d,%r13d
  400e0a:	cmp    %r13d,%ebp
  400e0d:	jbe    400e68 <ck_barrier_tournament_init+0x138>
  400e0f:	movl   $0x4,(%rdx)
  400e15:	nopl   (%rax)
  400e18:	cmp    %ebx,%edi
  400e1a:	jne    400db0 <ck_barrier_tournament_init+0x80>
  400e1c:	movl   $0x3,(%rdx)
  400e22:	mov    %r9d,%edi
  400e25:	add    $0x18,%rdx
  400e29:	sub    %ebx,%edi
  400e2b:	mov    %ecx,%ebx
  400e2d:	add    (%r14,%rdi,8),%r8
  400e31:	lea    (%rcx,%rcx,1),%edi
  400e34:	add    $0x10,%r8
  400e38:	mov    %r8,-0x10(%rdx)
  400e3c:	cmp    %rdx,%r11
  400e3f:	jne    400de5 <ck_barrier_tournament_init+0xb5>
  400e41:	add    $0x1,%rsi
  400e45:	cmp    %esi,%ebp
  400e47:	ja     400d78 <ck_barrier_tournament_init+0x48>
  400e4d:	mov    0x8(%rsp),%rax
  400e52:	mov    %r14,0x8(%rax)
  400e56:	add    $0x18,%rsp
  400e5a:	pop    %rbx
  400e5b:	pop    %rbp
  400e5c:	pop    %r12
  400e5e:	pop    %r13
  400e60:	pop    %r14
  400e62:	pop    %r15
  400e64:	retq   
  400e65:	nopl   (%rax)
  400e68:	cmp    %r12d,%ebp
  400e6b:	ja     400e18 <ck_barrier_tournament_init+0xe8>
  400e6d:	movl   $0x0,(%rdx)
  400e73:	jmp    400e18 <ck_barrier_tournament_init+0xe8>
  400e75:	nopl   (%rax)
  400e78:	mov    (%rdx),%edi
  400e7a:	cmp    $0x3,%edi
  400e7d:	je     400e22 <ck_barrier_tournament_init+0xf2>
  400e7f:	cmp    $0x1,%edi
  400e82:	je     400dc7 <ck_barrier_tournament_init+0x97>
  400e88:	cmp    $0x4,%edi
  400e8b:	jne    400dd7 <ck_barrier_tournament_init+0xa7>
  400e91:	jmpq   400dc7 <ck_barrier_tournament_init+0x97>
  400e96:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400ea0 <ck_barrier_tournament>:
  400ea0:	mov    0x8(%rdi),%rdx
  400ea4:	cmpl   $0x1,0x4(%rdi)
  400ea8:	je     400f6a <ck_barrier_tournament+0xca>
  400eae:	mov    0x4(%rsi),%eax
  400eb1:	mov    $0x1,%r8d
  400eb7:	mov    (%rdx,%rax,8),%r9
  400ebb:	mov    $0x18,%eax
  400ec0:	lea    (%r9,%rax,1),%rdi
  400ec4:	mov    (%rdi),%ecx
  400ec6:	cmp    $0x3,%ecx
  400ec9:	je     400ef0 <ck_barrier_tournament+0x50>
  400ecb:	cmp    $0x4,%ecx
  400ece:	je     400fb0 <ck_barrier_tournament+0x110>
  400ed4:	cmp    $0x1,%ecx
  400ed7:	je     400f70 <ck_barrier_tournament+0xd0>
  400edd:	add    $0x18,%rax
  400ee1:	add    $0x1,%r8d
  400ee5:	lea    (%r9,%rax,1),%rdi
  400ee9:	mov    (%rdi),%ecx
  400eeb:	cmp    $0x3,%ecx
  400eee:	jne    400ecb <ck_barrier_tournament+0x2b>
  400ef0:	mov    0x8(%rdi),%rcx
  400ef4:	mov    (%rsi),%edi
  400ef6:	mov    %edi,(%rcx)
  400ef8:	mov    0x4(%rsi),%ecx
  400efb:	mov    (%rdx,%rcx,8),%rcx
  400eff:	mov    0x10(%rcx,%rax,1),%ecx
  400f03:	cmp    (%rsi),%ecx
  400f05:	je     400f21 <ck_barrier_tournament+0x81>
  400f07:	nopw   0x0(%rax,%rax,1)
  400f10:	pause  
  400f12:	mov    0x4(%rsi),%ecx
  400f15:	mov    (%rdx,%rcx,8),%rcx
  400f19:	mov    0x10(%rcx,%rax,1),%ecx
  400f1d:	cmp    %ecx,(%rsi)
  400f1f:	jne    400f10 <ck_barrier_tournament+0x70>
  400f21:	mov    0x4(%rsi),%eax
  400f24:	sub    $0x1,%r8d
  400f28:	movslq %r8d,%r8
  400f2b:	mov    (%rdx,%rax,8),%r9
  400f2f:	lea    (%r8,%r8,2),%rax
  400f33:	shl    $0x3,%rax
  400f37:	lea    (%r9,%rax,1),%rdi
  400f3b:	mov    (%rdi),%ecx
  400f3d:	cmp    $0x2,%ecx
  400f40:	je     400f65 <ck_barrier_tournament+0xc5>
  400f42:	cmp    $0x4,%ecx
  400f45:	jne    400f56 <ck_barrier_tournament+0xb6>
  400f47:	mov    0x8(%rdi),%rcx
  400f4b:	mov    (%rsi),%edi
  400f4d:	mov    %edi,(%rcx)
  400f4f:	mov    0x4(%rsi),%ecx
  400f52:	mov    (%rdx,%rcx,8),%r9
  400f56:	sub    $0x18,%rax
  400f5a:	lea    (%r9,%rax,1),%rdi
  400f5e:	mov    (%rdi),%ecx
  400f60:	cmp    $0x2,%ecx
  400f63:	jne    400f42 <ck_barrier_tournament+0xa2>
  400f65:	mfence 
  400f68:	notl   (%rsi)
  400f6a:	repz retq 
  400f6c:	nopl   0x0(%rax)
  400f70:	mov    0x10(%rdi),%edi
  400f73:	mov    (%rsi),%ecx
  400f75:	cmp    %ecx,%edi
  400f77:	je     400f93 <ck_barrier_tournament+0xf3>
  400f79:	nopl   0x0(%rax)
  400f80:	pause  
  400f82:	mov    0x4(%rsi),%ecx
  400f85:	mov    (%rdx,%rcx,8),%rcx
  400f89:	mov    0x10(%rcx,%rax,1),%edi
  400f8d:	mov    (%rsi),%ecx
  400f8f:	cmp    %edi,%ecx
  400f91:	jne    400f80 <ck_barrier_tournament+0xe0>
  400f93:	mov    0x4(%rsi),%edi
  400f96:	mov    (%rdx,%rdi,8),%rdi
  400f9a:	mov    0x8(%rdi,%rax,1),%rax
  400f9f:	mov    %ecx,(%rax)
  400fa1:	jmpq   400f21 <ck_barrier_tournament+0x81>
  400fa6:	nopw   %cs:0x0(%rax,%rax,1)
  400fb0:	mov    0x10(%rdi),%ecx
  400fb3:	cmp    (%rsi),%ecx
  400fb5:	je     400fd1 <ck_barrier_tournament+0x131>
  400fb7:	nopw   0x0(%rax,%rax,1)
  400fc0:	pause  
  400fc2:	mov    0x4(%rsi),%ecx
  400fc5:	mov    (%rdx,%rcx,8),%rcx
  400fc9:	mov    0x10(%rcx,%rax,1),%ecx
  400fcd:	cmp    %ecx,(%rsi)
  400fcf:	jne    400fc0 <ck_barrier_tournament+0x120>
  400fd1:	mov    0x4(%rsi),%ecx
  400fd4:	mov    (%rdx,%rcx,8),%r9
  400fd8:	jmpq   400edd <ck_barrier_tournament+0x3d>
  400fdd:	nopl   (%rax)

0000000000400fe0 <__libc_csu_init>:
  400fe0:	push   %r15
  400fe2:	push   %r14
  400fe4:	mov    %edi,%r15d
  400fe7:	push   %r13
  400fe9:	push   %r12
  400feb:	lea    0x200dfe(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400ff2:	push   %rbp
  400ff3:	lea    0x200dfe(%rip),%rbp        # 601df8 <__init_array_end>
  400ffa:	push   %rbx
  400ffb:	mov    %rsi,%r14
  400ffe:	mov    %rdx,%r13
  401001:	sub    %r12,%rbp
  401004:	sub    $0x8,%rsp
  401008:	sar    $0x3,%rbp
  40100c:	callq  4006c8 <_init>
  401011:	test   %rbp,%rbp
  401014:	je     401036 <__libc_csu_init+0x56>
  401016:	xor    %ebx,%ebx
  401018:	nopl   0x0(%rax,%rax,1)
  401020:	mov    %r13,%rdx
  401023:	mov    %r14,%rsi
  401026:	mov    %r15d,%edi
  401029:	callq  *(%r12,%rbx,8)
  40102d:	add    $0x1,%rbx
  401031:	cmp    %rbx,%rbp
  401034:	jne    401020 <__libc_csu_init+0x40>
  401036:	add    $0x8,%rsp
  40103a:	pop    %rbx
  40103b:	pop    %rbp
  40103c:	pop    %r12
  40103e:	pop    %r13
  401040:	pop    %r14
  401042:	pop    %r15
  401044:	retq   
  401045:	nop
  401046:	nopw   %cs:0x0(%rax,%rax,1)

0000000000401050 <__libc_csu_fini>:
  401050:	repz retq 

Disassembly of section .fini:

0000000000401054 <_fini>:
  401054:	sub    $0x8,%rsp
  401058:	add    $0x8,%rsp
  40105c:	retq   
