// TC_OUT ck_barrier_dissemination,0x400ee8,0x400eef,0x0(%rdx),0x4(%rsi)
// TC_OUT thread,0x400be0,0x400bee,0x0(0x6020a0),0x0(0x6028c0)
barrier_dissemination:     file format elf64-x86-64


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
  40078a:	sub    $0x18,%rsp
  40078e:	cmp    $0x2,%edi
  400791:	jle    400982 <main+0x202>
  400797:	mov    0x8(%rsi),%rdi
  40079b:	mov    %rsi,%r14
  40079e:	mov    $0xa,%edx
  4007a3:	xor    %esi,%esi
  4007a5:	callq  400720 <strtol@plt>
  4007aa:	test   %eax,%eax
  4007ac:	mov    %rax,%rbx
  4007af:	mov    %eax,0x20210b(%rip)        # 6028c0 <nthr>
  4007b5:	jle    40099e <main+0x21e>
  4007bb:	movslq %eax,%rbp
  4007be:	lea    0x0(,%rbp,8),%r12
  4007c6:	mov    %r12,%rdi
  4007c9:	callq  400730 <malloc@plt>
  4007ce:	test   %rax,%rax
  4007d1:	mov    %rax,%r13
  4007d4:	je     400990 <main+0x210>
  4007da:	mov    0x10(%r14),%rdi
  4007de:	xor    %esi,%esi
  4007e0:	mov    $0xa,%edx
  4007e5:	callq  400720 <strtol@plt>
  4007ea:	mov    %rbp,%rdi
  4007ed:	mov    %eax,0x2020d5(%rip)        # 6028c8 <a>
  4007f3:	shl    $0x5,%rdi
  4007f7:	callq  400730 <malloc@plt>
  4007fc:	test   %rax,%rax
  4007ff:	mov    %rax,%rbp
  400802:	je     400964 <main+0x1e4>
  400808:	mov    %r12,%rdi
  40080b:	callq  400730 <malloc@plt>
  400810:	test   %rax,%rax
  400813:	mov    %rax,%r14
  400816:	je     400964 <main+0x1e4>
  40081c:	mov    %ebx,%edi
  40081e:	callq  400e20 <ck_barrier_dissemination_size>
  400823:	mov    0x202097(%rip),%ecx        # 6028c0 <nthr>
  400829:	test   %ecx,%ecx
  40082b:	mov    %ecx,0xc(%rsp)
  40082f:	jle    40086d <main+0xed>
  400831:	movslq %eax,%rbx
  400834:	mov    0xc(%rsp),%eax
  400838:	mov    %r14,%r15
  40083b:	shl    $0x4,%rbx
  40083f:	sub    $0x1,%eax
  400842:	lea    0x8(%r14,%rax,8),%r12
  400847:	nopw   0x0(%rax,%rax,1)
  400850:	mov    %rbx,%rdi
  400853:	callq  400730 <malloc@plt>
  400858:	test   %rax,%rax
  40085b:	mov    %rax,(%r15)
  40085e:	je     400964 <main+0x1e4>
  400864:	add    $0x8,%r15
  400868:	cmp    %r12,%r15
  40086b:	jne    400850 <main+0xd0>
  40086d:	mov    0xc(%rsp),%edx
  400871:	mov    %r14,%rsi
  400874:	mov    %rbp,%rdi
  400877:	xor    %ebx,%ebx
  400879:	mov    %r13,%r12
  40087c:	lea    0x2dd(%rip),%r14        # 400b60 <thread>
  400883:	callq  400c80 <ck_barrier_dissemination_init>
  400888:	mov    0x201769(%rip),%r15        # 601ff8 <_DYNAMIC+0x1f0>
  40088f:	lea    0x724(%rip),%rdi        # 400fba <__dso_handle+0x22>
  400896:	mov    $0x1d,%edx
  40089b:	mov    $0x1,%esi
  4008a0:	mov    (%r15),%rcx
  4008a3:	callq  400770 <fwrite@plt>
  4008a8:	mov    0x202012(%rip),%edx        # 6028c0 <nthr>
  4008ae:	test   %edx,%edx
  4008b0:	jle    4008df <main+0x15f>
  4008b2:	nopw   0x0(%rax,%rax,1)
  4008b8:	xor    %esi,%esi
  4008ba:	mov    %rbp,%rcx
  4008bd:	mov    %r14,%rdx
  4008c0:	mov    %r12,%rdi
  4008c3:	callq  4006f0 <pthread_create@plt>
  4008c8:	test   %eax,%eax
  4008ca:	jne    400972 <main+0x1f2>
  4008d0:	add    $0x1,%ebx
  4008d3:	add    $0x8,%r12
  4008d7:	cmp    %ebx,0x201fe3(%rip)        # 6028c0 <nthr>
  4008dd:	jg     4008b8 <main+0x138>
  4008df:	mov    (%r15),%rcx
  4008e2:	lea    0x6ef(%rip),%rdi        # 400fd8 <__dso_handle+0x40>
  4008e9:	mov    $0x5,%edx
  4008ee:	mov    $0x1,%esi
  4008f3:	mov    $0x1,%ebx
  4008f8:	callq  400770 <fwrite@plt>
  4008fd:	mov    (%r15),%rcx
  400900:	lea    0x7b9(%rip),%rdi        # 4010c0 <__dso_handle+0x128>
  400907:	mov    $0x37,%edx
  40090c:	mov    $0x1,%esi
  400911:	callq  400770 <fwrite@plt>
  400916:	mov    0x201fa4(%rip),%eax        # 6028c0 <nthr>
  40091c:	test   %eax,%eax
  40091e:	jle    40093a <main+0x1ba>
  400920:	mov    -0x8(%r13,%rbx,8),%rdi
  400925:	xor    %esi,%esi
  400927:	callq  400740 <pthread_join@plt>
  40092c:	mov    %ebx,%eax
  40092e:	add    $0x1,%rbx
  400932:	cmp    %eax,0x201f88(%rip)        # 6028c0 <nthr>
  400938:	jg     400920 <main+0x1a0>
  40093a:	mov    (%r15),%rcx
  40093d:	lea    0x69a(%rip),%rdi        # 400fde <__dso_handle+0x46>
  400944:	mov    $0xe,%edx
  400949:	mov    $0x1,%esi
  40094e:	callq  400770 <fwrite@plt>
  400953:	add    $0x18,%rsp
  400957:	xor    %eax,%eax
  400959:	pop    %rbx
  40095a:	pop    %rbp
  40095b:	pop    %r12
  40095d:	pop    %r13
  40095f:	pop    %r14
  400961:	pop    %r15
  400963:	retq   
  400964:	lea    0x725(%rip),%rdi        # 401090 <__dso_handle+0xf8>
  40096b:	xor    %eax,%eax
  40096d:	callq  400ab0 <ck_error>
  400972:	lea    0x77f(%rip),%rdi        # 4010f8 <__dso_handle+0x160>
  400979:	mov    %ebx,%esi
  40097b:	xor    %eax,%eax
  40097d:	callq  400ab0 <ck_error>
  400982:	lea    0x667(%rip),%rdi        # 400ff0 <__dso_handle+0x58>
  400989:	xor    %eax,%eax
  40098b:	callq  400ab0 <ck_error>
  400990:	lea    0x6c9(%rip),%rdi        # 401060 <__dso_handle+0xc8>
  400997:	xor    %eax,%eax
  400999:	callq  400ab0 <ck_error>
  40099e:	lea    0x683(%rip),%rdi        # 401028 <__dso_handle+0x90>
  4009a5:	xor    %eax,%eax
  4009a7:	callq  400ab0 <ck_error>
  4009ac:	nopl   0x0(%rax)

00000000004009b0 <_start>:
  4009b0:	xor    %ebp,%ebp
  4009b2:	mov    %rdx,%r9
  4009b5:	pop    %rsi
  4009b6:	mov    %rsp,%rdx
  4009b9:	and    $0xfffffffffffffff0,%rsp
  4009bd:	push   %rax
  4009be:	push   %rsp
  4009bf:	mov    $0x400f80,%r8
  4009c6:	mov    $0x400f10,%rcx
  4009cd:	mov    $0x400780,%rdi
  4009d4:	callq  *0x20160e(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  4009da:	hlt    
  4009db:	nopl   0x0(%rax,%rax,1)

00000000004009e0 <deregister_tm_clones>:
  4009e0:	mov    $0x60206f,%eax
  4009e5:	push   %rbp
  4009e6:	sub    $0x602068,%rax
  4009ec:	cmp    $0xe,%rax
  4009f0:	mov    %rsp,%rbp
  4009f3:	jbe    400a10 <deregister_tm_clones+0x30>
  4009f5:	mov    $0x0,%eax
  4009fa:	test   %rax,%rax
  4009fd:	je     400a10 <deregister_tm_clones+0x30>
  4009ff:	pop    %rbp
  400a00:	mov    $0x602068,%edi
  400a05:	jmpq   *%rax
  400a07:	nopw   0x0(%rax,%rax,1)
  400a10:	pop    %rbp
  400a11:	retq   
  400a12:	nopl   0x0(%rax)
  400a16:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a20 <register_tm_clones>:
  400a20:	mov    $0x602068,%esi
  400a25:	push   %rbp
  400a26:	sub    $0x602068,%rsi
  400a2d:	sar    $0x3,%rsi
  400a31:	mov    %rsp,%rbp
  400a34:	mov    %rsi,%rax
  400a37:	shr    $0x3f,%rax
  400a3b:	add    %rax,%rsi
  400a3e:	sar    %rsi
  400a41:	je     400a58 <register_tm_clones+0x38>
  400a43:	mov    $0x0,%eax
  400a48:	test   %rax,%rax
  400a4b:	je     400a58 <register_tm_clones+0x38>
  400a4d:	pop    %rbp
  400a4e:	mov    $0x602068,%edi
  400a53:	jmpq   *%rax
  400a55:	nopl   (%rax)
  400a58:	pop    %rbp
  400a59:	retq   
  400a5a:	nopw   0x0(%rax,%rax,1)

0000000000400a60 <__do_global_dtors_aux>:
  400a60:	cmpb   $0x0,0x201619(%rip)        # 602080 <completed.6917>
  400a67:	jne    400a7a <__do_global_dtors_aux+0x1a>
  400a69:	push   %rbp
  400a6a:	mov    %rsp,%rbp
  400a6d:	callq  4009e0 <deregister_tm_clones>
  400a72:	pop    %rbp
  400a73:	movb   $0x1,0x201606(%rip)        # 602080 <completed.6917>
  400a7a:	repz retq 
  400a7c:	nopl   0x0(%rax)

0000000000400a80 <frame_dummy>:
  400a80:	mov    $0x601e00,%edi
  400a85:	cmpq   $0x0,(%rdi)
  400a89:	jne    400a90 <frame_dummy+0x10>
  400a8b:	jmp    400a20 <register_tm_clones>
  400a8d:	nopl   (%rax)
  400a90:	mov    $0x0,%eax
  400a95:	test   %rax,%rax
  400a98:	je     400a8b <frame_dummy+0xb>
  400a9a:	push   %rbp
  400a9b:	mov    %rsp,%rbp
  400a9e:	callq  *%rax
  400aa0:	pop    %rbp
  400aa1:	jmpq   400a20 <register_tm_clones>
  400aa6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400ab0 <ck_error>:
  400ab0:	sub    $0xd8,%rsp
  400ab7:	test   %al,%al
  400ab9:	mov    %rsi,0x28(%rsp)
  400abe:	mov    %rdx,0x30(%rsp)
  400ac3:	mov    %rcx,0x38(%rsp)
  400ac8:	mov    %r8,0x40(%rsp)
  400acd:	mov    %r9,0x48(%rsp)
  400ad2:	je     400b0b <ck_error+0x5b>
  400ad4:	movaps %xmm0,0x50(%rsp)
  400ad9:	movaps %xmm1,0x60(%rsp)
  400ade:	movaps %xmm2,0x70(%rsp)
  400ae3:	movaps %xmm3,0x80(%rsp)
  400aeb:	movaps %xmm4,0x90(%rsp)
  400af3:	movaps %xmm5,0xa0(%rsp)
  400afb:	movaps %xmm6,0xb0(%rsp)
  400b03:	movaps %xmm7,0xc0(%rsp)
  400b0b:	lea    0xe0(%rsp),%rax
  400b13:	mov    %rdi,%rsi
  400b16:	lea    0x8(%rsp),%rdx
  400b1b:	mov    %rax,0x10(%rsp)
  400b20:	lea    0x20(%rsp),%rax
  400b25:	movl   $0x8,0x8(%rsp)
  400b2d:	movl   $0x30,0xc(%rsp)
  400b35:	mov    %rax,0x18(%rsp)
  400b3a:	mov    0x2014b7(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400b41:	mov    (%rax),%rdi
  400b44:	callq  400750 <vfprintf@plt>
  400b49:	mov    $0x1,%edi
  400b4e:	callq  400760 <exit@plt>
  400b53:	nopl   (%rax)
  400b56:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b60 <thread>:
  400b60:	push   %r15
  400b62:	push   %r14
  400b64:	push   %r13
  400b66:	push   %r12
  400b68:	push   %rbp
  400b69:	push   %rbx
  400b6a:	mov    %rdi,%rbp
  400b6d:	sub    $0x88,%rsp
  400b74:	mov    0x201d4e(%rip),%edx        # 6028c8 <a>
  400b7a:	lock xadd %edx,0x201d4a(%rip)        # 6028cc <a+0x4>
  400b82:	xor    %eax,%eax
  400b84:	mov    %rsp,%rdi
  400b87:	mov    $0x10,%ecx
  400b8c:	rep stos %rax,%es:(%rdi)
  400b8f:	and    $0x3,%edx
  400b92:	mov    $0x1,%eax
  400b97:	mov    $0xba,%edi
  400b9c:	mov    %edx,%ecx
  400b9e:	mov    %rsp,%rbx
  400ba1:	shl    %cl,%rax
  400ba4:	mov    %rax,(%rsp)
  400ba8:	xor    %eax,%eax
  400baa:	callq  400710 <syscall@plt>
  400baf:	mov    %rsp,%rdx
  400bb2:	mov    $0x80,%esi
  400bb7:	mov    %eax,%edi
  400bb9:	callq  400700 <sched_setaffinity@plt>
  400bbe:	mov    %rsp,%rsi
  400bc1:	mov    %rbp,%rdi
  400bc4:	callq  400e00 <ck_barrier_dissemination_subscribe>
  400bc9:	lock incl 0x2014d0(%rip)        # 6020a0 <barrier_wait>
  400bd0:	mov    0x2014ca(%rip),%eax        # 6020a0 <barrier_wait>
  400bd6:	cmp    %eax,0x201ce4(%rip)        # 6028c0 <nthr>
  400bdc:	je     400bf0 <thread+0x90>
  400bde:	xchg   %ax,%ax
  400be0:	pause  
  400be2:	mov    0x2014b8(%rip),%eax        # 6020a0 <barrier_wait>
  400be8:	cmp    %eax,0x201cd2(%rip)        # 6028c0 <nthr>
  400bee:	jne    400be0 <thread+0x80>
  400bf0:	lea    0x2014c9(%rip),%r12        # 6020c0 <counters>
  400bf7:	xor    %r13d,%r13d
  400bfa:	nopw   0x0(%rax,%rax,1)
  400c00:	mov    %r13d,%r15d
  400c03:	and    $0x1ff,%r15d
  400c0a:	movslq %r15d,%rax
  400c0d:	lea    (%r12,%rax,4),%r14
  400c11:	lock incl (%r14)
  400c15:	mov    %rbx,%rsi
  400c18:	mov    %rbp,%rdi
  400c1b:	callq  400ea0 <ck_barrier_dissemination>
  400c20:	mov    (%r14),%ecx
  400c23:	lea    0x1(%r13),%eax
  400c27:	mov    0x201c92(%rip),%r8d        # 6028c0 <nthr>
  400c2e:	sar    $0x9,%eax
  400c31:	add    $0x1,%eax
  400c34:	imul   %r8d,%eax
  400c38:	cmp    %ecx,%eax
  400c3a:	jne    400c5d <thread+0xfd>
  400c3c:	add    $0x2,%r13d
  400c40:	cmp    $0x4c4b40,%r13d
  400c47:	jne    400c00 <thread+0xa0>
  400c49:	add    $0x88,%rsp
  400c50:	xor    %eax,%eax
  400c52:	pop    %rbx
  400c53:	pop    %rbp
  400c54:	pop    %r12
  400c56:	pop    %r13
  400c58:	pop    %r14
  400c5a:	pop    %r15
  400c5c:	retq   
  400c5d:	lea    0x33c(%rip),%rdi        # 400fa0 <__dso_handle+0x8>
  400c64:	mov    %r13d,%edx
  400c67:	mov    %r15d,%esi
  400c6a:	xor    %eax,%eax
  400c6c:	callq  400ab0 <ck_error>
  400c71:	nopw   %cs:0x0(%rax,%rax,1)
  400c7b:	nopl   0x0(%rax,%rax,1)

0000000000400c80 <ck_barrier_dissemination_init>:
  400c80:	push   %r14
  400c82:	push   %r13
  400c84:	mov    %edx,%r11d
  400c87:	push   %r12
  400c89:	lea    -0x1(%rdx),%r12d
  400c8d:	push   %rbp
  400c8e:	mov    %edx,(%rdi)
  400c90:	mov    %edx,%ebp
  400c92:	xor    %r14d,%r14d
  400c95:	mov    %r12d,%eax
  400c98:	and    %r12d,%ebp
  400c9b:	mov    $0x10,%ecx
  400ca0:	shr    %eax
  400ca2:	push   %rbx
  400ca3:	or     %r12d,%eax
  400ca6:	mov    %eax,%edx
  400ca8:	shr    $0x2,%edx
  400cab:	or     %edx,%eax
  400cad:	mov    %eax,%edx
  400caf:	shr    $0x4,%edx
  400cb2:	or     %edx,%eax
  400cb4:	mov    %eax,%edx
  400cb6:	shr    $0x8,%edx
  400cb9:	or     %edx,%eax
  400cbb:	mov    %eax,%edx
  400cbd:	shr    $0x10,%edx
  400cc0:	or     %edx,%eax
  400cc2:	add    $0x1,%eax
  400cc5:	test   $0xaaaaaaaa,%eax
  400cca:	mov    %eax,%edx
  400ccc:	setne  %r14b
  400cd0:	and    $0xffff0000,%edx
  400cd6:	cmovne %ecx,%edx
  400cd9:	mov    $0x8,%ecx
  400cde:	or     %edx,%r14d
  400ce1:	mov    %eax,%edx
  400ce3:	and    $0xff00ff00,%edx
  400ce9:	cmovne %ecx,%edx
  400cec:	mov    $0x4,%ecx
  400cf1:	or     %edx,%r14d
  400cf4:	mov    %eax,%edx
  400cf6:	and    $0xf0f0f0f0,%edx
  400cfc:	cmovne %ecx,%edx
  400cff:	or     %edx,%r14d
  400d02:	and    $0xcccccccc,%eax
  400d07:	mov    $0x2,%edx
  400d0c:	cmovne %edx,%eax
  400d0f:	or     %eax,%r14d
  400d12:	mov    %r14d,0x4(%rdi)
  400d16:	movl   $0x0,0x8(%rdi)
  400d1d:	test   %r11d,%r11d
  400d20:	je     400df5 <ck_barrier_dissemination_init+0x175>
  400d26:	mov    %r12d,%edx
  400d29:	mov    %r14d,%ecx
  400d2c:	lea    0x18(%rdi),%rax
  400d30:	lea    0x8(%rsi,%rdx,8),%r8
  400d35:	shl    $0x4,%rcx
  400d39:	nopl   0x0(%rax)
  400d40:	mov    (%rsi),%rdx
  400d43:	add    $0x8,%rsi
  400d47:	add    $0x20,%rax
  400d4b:	mov    %rdx,-0x28(%rax)
  400d4f:	mov    %rcx,%rdx
  400d52:	add    -0x8(%rsi),%rdx
  400d56:	mov    %rdx,-0x20(%rax)
  400d5a:	cmp    %r8,%rsi
  400d5d:	jne    400d40 <ck_barrier_dissemination_init+0xc0>
  400d5f:	lea    -0x1(%r14),%ebx
  400d63:	lea    0x10(%rdi),%r13
  400d67:	xor    %r10d,%r10d
  400d6a:	add    $0x1,%rbx
  400d6e:	shl    $0x4,%rbx
  400d72:	nopw   0x0(%rax,%rax,1)
  400d78:	test   %r14d,%r14d
  400d7b:	je     400de8 <ck_barrier_dissemination_init+0x168>
  400d7d:	mov    0x0(%r13),%r9
  400d81:	mov    0x8(%r13),%r8
  400d85:	xor    %ecx,%ecx
  400d87:	mov    $0x1,%esi
  400d8c:	jmp    400dd3 <ck_barrier_dissemination_init+0x153>
  400d8e:	xchg   %ax,%ax
  400d90:	lea    (%r10,%rsi,1),%edx
  400d94:	and    %r12d,%edx
  400d97:	mov    %edx,%edx
  400d99:	mov    %rcx,%rax
  400d9c:	add    %esi,%esi
  400d9e:	shl    $0x5,%rdx
  400da2:	add    %rdi,%rdx
  400da5:	add    0x10(%rdx),%rax
  400da9:	mov    %rax,0x8(%r9,%rcx,1)
  400dae:	mov    %rcx,%rax
  400db1:	add    0x18(%rdx),%rax
  400db5:	movl   $0x0,(%r8,%rcx,1)
  400dbd:	mov    %rax,0x8(%r8,%rcx,1)
  400dc2:	movl   $0x0,(%r9,%rcx,1)
  400dca:	add    $0x10,%rcx
  400dce:	cmp    %rcx,%rbx
  400dd1:	je     400de8 <ck_barrier_dissemination_init+0x168>
  400dd3:	test   %ebp,%ebp
  400dd5:	je     400d90 <ck_barrier_dissemination_init+0x110>
  400dd7:	lea    (%r10,%rsi,1),%eax
  400ddb:	xor    %edx,%edx
  400ddd:	div    %r11d
  400de0:	jmp    400d97 <ck_barrier_dissemination_init+0x117>
  400de2:	nopw   0x0(%rax,%rax,1)
  400de8:	add    $0x1,%r10d
  400dec:	add    $0x20,%r13
  400df0:	cmp    %r10d,%r11d
  400df3:	jne    400d78 <ck_barrier_dissemination_init+0xf8>
  400df5:	pop    %rbx
  400df6:	pop    %rbp
  400df7:	pop    %r12
  400df9:	pop    %r13
  400dfb:	pop    %r14
  400dfd:	retq   
  400dfe:	xchg   %ax,%ax

0000000000400e00 <ck_barrier_dissemination_subscribe>:
  400e00:	movl   $0x0,(%rsi)
  400e06:	movl   $0xffffffff,0x4(%rsi)
  400e0d:	mov    $0x1,%eax
  400e12:	lock xadd %eax,0x8(%rdi)
  400e17:	mov    %eax,0x8(%rsi)
  400e1a:	retq   
  400e1b:	nopl   0x0(%rax,%rax,1)

0000000000400e20 <ck_barrier_dissemination_size>:
  400e20:	sub    $0x1,%edi
  400e23:	mov    $0x10,%esi
  400e28:	mov    %edi,%edx
  400e2a:	shr    %edx
  400e2c:	or     %edi,%edx
  400e2e:	mov    %edx,%edi
  400e30:	shr    $0x2,%edi
  400e33:	or     %edi,%edx
  400e35:	mov    %edx,%edi
  400e37:	shr    $0x4,%edi
  400e3a:	or     %edi,%edx
  400e3c:	mov    %edx,%eax
  400e3e:	shr    $0x8,%eax
  400e41:	or     %eax,%edx
  400e43:	mov    %edx,%eax
  400e45:	shr    $0x10,%eax
  400e48:	or     %eax,%edx
  400e4a:	xor    %eax,%eax
  400e4c:	add    $0x1,%edx
  400e4f:	test   $0xaaaaaaaa,%edx
  400e55:	mov    %edx,%ecx
  400e57:	setne  %al
  400e5a:	and    $0xffff0000,%ecx
  400e60:	cmovne %esi,%ecx
  400e63:	mov    $0x8,%esi
  400e68:	or     %ecx,%eax
  400e6a:	mov    %edx,%ecx
  400e6c:	and    $0xff00ff00,%ecx
  400e72:	cmovne %esi,%ecx
  400e75:	mov    $0x4,%esi
  400e7a:	or     %ecx,%eax
  400e7c:	mov    %edx,%ecx
  400e7e:	and    $0xf0f0f0f0,%ecx
  400e84:	cmovne %esi,%ecx
  400e87:	or     %ecx,%eax
  400e89:	and    $0xcccccccc,%edx
  400e8f:	mov    $0x2,%ecx
  400e94:	cmovne %ecx,%edx
  400e97:	or     %eax,%edx
  400e99:	lea    (%rdx,%rdx,1),%eax
  400e9c:	retq   
  400e9d:	nopl   (%rax)

0000000000400ea0 <ck_barrier_dissemination>:
  400ea0:	mov    0x4(%rdi),%eax
  400ea3:	test   %eax,%eax
  400ea5:	je     400efa <ck_barrier_dissemination+0x5a>
  400ea7:	lea    -0x1(%rax),%r9d
  400eab:	xor    %ecx,%ecx
  400ead:	add    $0x1,%r9
  400eb1:	shl    $0x4,%r9
  400eb5:	nopl   (%rax)
  400eb8:	mov    0x8(%rsi),%eax
  400ebb:	movslq (%rsi),%rdx
  400ebe:	mov    %rcx,%r10
  400ec1:	mov    0x4(%rsi),%r8d
  400ec5:	shl    $0x5,%rax
  400ec9:	add    %rdi,%rax
  400ecc:	add    0x10(%rax,%rdx,8),%r10
  400ed1:	mov    %r10,%rdx
  400ed4:	mov    0x8(%r10),%rax
  400ed8:	mov    %r8d,(%rax)
  400edb:	mov    (%r10),%eax
  400ede:	cmp    %eax,0x4(%rsi)
  400ee1:	je     400ef1 <ck_barrier_dissemination+0x51>
  400ee3:	nopl   0x0(%rax,%rax,1)
  400ee8:	pause  
  400eea:	mov    (%rdx),%eax
  400eec:	cmp    %eax,0x4(%rsi)
  400eef:	jne    400ee8 <ck_barrier_dissemination+0x48>
  400ef1:	add    $0x10,%rcx
  400ef5:	cmp    %rcx,%r9
  400ef8:	jne    400eb8 <ck_barrier_dissemination+0x18>
  400efa:	mov    (%rsi),%edx
  400efc:	cmp    $0x1,%edx
  400eff:	jne    400f04 <ck_barrier_dissemination+0x64>
  400f01:	notl   0x4(%rsi)
  400f04:	mov    $0x1,%eax
  400f09:	sub    %edx,%eax
  400f0b:	mov    %eax,(%rsi)
  400f0d:	retq   
  400f0e:	xchg   %ax,%ax

0000000000400f10 <__libc_csu_init>:
  400f10:	push   %r15
  400f12:	push   %r14
  400f14:	mov    %edi,%r15d
  400f17:	push   %r13
  400f19:	push   %r12
  400f1b:	lea    0x200ece(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400f22:	push   %rbp
  400f23:	lea    0x200ece(%rip),%rbp        # 601df8 <__init_array_end>
  400f2a:	push   %rbx
  400f2b:	mov    %rsi,%r14
  400f2e:	mov    %rdx,%r13
  400f31:	sub    %r12,%rbp
  400f34:	sub    $0x8,%rsp
  400f38:	sar    $0x3,%rbp
  400f3c:	callq  4006c8 <_init>
  400f41:	test   %rbp,%rbp
  400f44:	je     400f66 <__libc_csu_init+0x56>
  400f46:	xor    %ebx,%ebx
  400f48:	nopl   0x0(%rax,%rax,1)
  400f50:	mov    %r13,%rdx
  400f53:	mov    %r14,%rsi
  400f56:	mov    %r15d,%edi
  400f59:	callq  *(%r12,%rbx,8)
  400f5d:	add    $0x1,%rbx
  400f61:	cmp    %rbx,%rbp
  400f64:	jne    400f50 <__libc_csu_init+0x40>
  400f66:	add    $0x8,%rsp
  400f6a:	pop    %rbx
  400f6b:	pop    %rbp
  400f6c:	pop    %r12
  400f6e:	pop    %r13
  400f70:	pop    %r14
  400f72:	pop    %r15
  400f74:	retq   
  400f75:	nop
  400f76:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400f80 <__libc_csu_fini>:
  400f80:	repz retq 

Disassembly of section .fini:

0000000000400f84 <_fini>:
  400f84:	sub    $0x8,%rsp
  400f88:	add    $0x8,%rsp
  400f8c:	retq   
