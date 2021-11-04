// TC_OUT thread,0x400e20,0x400e2c,0x0(0x602098)
// TC_OUT thread,0x400e40,0x400e4a,0x0(0x60209c)
// TC_OUT thread,0x400f00,0x400f06,0x0(%rdx)
// TC_OUT thread,0x400f02,0x400f1c,0x0(%rdx)
// TC_OUT thread_recursive,0x400b60,0x400b8b,0x0(%rcx),0x0(0x60208c)
// TC_OUT thread_recursive,0x400ba0,0x400bb1,0x0(0x602088)
// TC_OUT thread_recursive,0x400bc0,0x400bca,0x0(0x60208c)
// TC_OUT thread_recursive,0x400be0,0x400bf1,0x0(0x602088)
// TC_OUT thread_recursive,0x400c00,0x400c0a,0x0(0x60208c)
// TC_OUT thread_recursive,0x400c20,0x400c31,0x0(0x602088)
// TC_OUT thread_recursive,0x400c40,0x400c4a,0x0(0x60208c)
// TC_OUT thread_recursive,0x400d58,0x400d5e,0x0(%rcx)
// TC_OUT thread_recursive,0x400d5a,0x400d74,0x0(%rcx)

validate:     file format elf64-x86-64


Disassembly of section .init:

0000000000400770 <_init>:
  400770:	sub    $0x8,%rsp
  400774:	mov    0x201875(%rip),%rax        # 601ff0 <_DYNAMIC+0x1e8>
  40077b:	test   %rax,%rax
  40077e:	je     400782 <_init+0x12>
  400780:	callq  *%rax
  400782:	add    $0x8,%rsp
  400786:	retq   

Disassembly of section .plt:

0000000000400790 <pthread_create@plt-0x10>:
  400790:	pushq  0x201872(%rip)        # 602008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400796:	jmpq   *0x201874(%rip)        # 602010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40079c:	nopl   0x0(%rax)

00000000004007a0 <pthread_create@plt>:
  4007a0:	jmpq   *0x201872(%rip)        # 602018 <_GLOBAL_OFFSET_TABLE_+0x18>
  4007a6:	pushq  $0x0
  4007ab:	jmpq   400790 <_init+0x20>

00000000004007b0 <sched_setaffinity@plt>:
  4007b0:	jmpq   *0x20186a(%rip)        # 602020 <_GLOBAL_OFFSET_TABLE_+0x20>
  4007b6:	pushq  $0x1
  4007bb:	jmpq   400790 <_init+0x20>

00000000004007c0 <fputc@plt>:
  4007c0:	jmpq   *0x201862(%rip)        # 602028 <_GLOBAL_OFFSET_TABLE_+0x28>
  4007c6:	pushq  $0x2
  4007cb:	jmpq   400790 <_init+0x20>

00000000004007d0 <fprintf@plt>:
  4007d0:	jmpq   *0x20185a(%rip)        # 602030 <_GLOBAL_OFFSET_TABLE_+0x30>
  4007d6:	pushq  $0x3
  4007db:	jmpq   400790 <_init+0x20>

00000000004007e0 <syscall@plt>:
  4007e0:	jmpq   *0x201852(%rip)        # 602038 <_GLOBAL_OFFSET_TABLE_+0x38>
  4007e6:	pushq  $0x4
  4007eb:	jmpq   400790 <_init+0x20>

00000000004007f0 <strtol@plt>:
  4007f0:	jmpq   *0x20184a(%rip)        # 602040 <_GLOBAL_OFFSET_TABLE_+0x40>
  4007f6:	pushq  $0x5
  4007fb:	jmpq   400790 <_init+0x20>

0000000000400800 <malloc@plt>:
  400800:	jmpq   *0x201842(%rip)        # 602048 <_GLOBAL_OFFSET_TABLE_+0x48>
  400806:	pushq  $0x6
  40080b:	jmpq   400790 <_init+0x20>

0000000000400810 <perror@plt>:
  400810:	jmpq   *0x20183a(%rip)        # 602050 <_GLOBAL_OFFSET_TABLE_+0x50>
  400816:	pushq  $0x7
  40081b:	jmpq   400790 <_init+0x20>

0000000000400820 <pthread_join@plt>:
  400820:	jmpq   *0x201832(%rip)        # 602058 <_GLOBAL_OFFSET_TABLE_+0x58>
  400826:	pushq  $0x8
  40082b:	jmpq   400790 <_init+0x20>

0000000000400830 <vfprintf@plt>:
  400830:	jmpq   *0x20182a(%rip)        # 602060 <_GLOBAL_OFFSET_TABLE_+0x60>
  400836:	pushq  $0x9
  40083b:	jmpq   400790 <_init+0x20>

0000000000400840 <exit@plt>:
  400840:	jmpq   *0x201822(%rip)        # 602068 <_GLOBAL_OFFSET_TABLE_+0x68>
  400846:	pushq  $0xa
  40084b:	jmpq   400790 <_init+0x20>

0000000000400850 <fwrite@plt>:
  400850:	jmpq   *0x20181a(%rip)        # 602070 <_GLOBAL_OFFSET_TABLE_+0x70>
  400856:	pushq  $0xb
  40085b:	jmpq   400790 <_init+0x20>

Disassembly of section .text:

0000000000400860 <main>:
  400860:	push   %rbp
  400861:	push   %rbx
  400862:	sub    $0x8,%rsp
  400866:	cmp    $0x3,%edi
  400869:	jne    4008ea <main+0x8a>
  40086b:	mov    0x8(%rsi),%rdi
  40086f:	mov    %rsi,%rbp
  400872:	mov    $0xa,%edx
  400877:	xor    %esi,%esi
  400879:	callq  4007f0 <strtol@plt>
  40087e:	test   %eax,%eax
  400880:	mov    %eax,0x20181a(%rip)        # 6020a0 <nthr>
  400886:	jle    400906 <main+0xa6>
  400888:	cltq   
  40088a:	lea    0x0(,%rax,8),%rdi
  400892:	callq  400800 <malloc@plt>
  400897:	test   %rax,%rax
  40089a:	mov    %rax,%rbx
  40089d:	je     4008f8 <main+0x98>
  40089f:	mov    0x10(%rbp),%rdi
  4008a3:	mov    $0xa,%edx
  4008a8:	xor    %esi,%esi
  4008aa:	callq  4007f0 <strtol@plt>
  4008af:	lea    0x9b2(%rip),%rdx        # 401268 <__dso_handle+0x160>
  4008b6:	lea    0x543(%rip),%rsi        # 400e00 <thread>
  4008bd:	mov    %rbx,%rdi
  4008c0:	mov    %eax,0x2017e2(%rip)        # 6020a8 <a>
  4008c6:	callq  400fb0 <rwlock_test>
  4008cb:	lea    0x99e(%rip),%rdx        # 401270 <__dso_handle+0x168>
  4008d2:	lea    0x257(%rip),%rsi        # 400b30 <thread_recursive>
  4008d9:	mov    %rbx,%rdi
  4008dc:	callq  400fb0 <rwlock_test>
  4008e1:	add    $0x8,%rsp
  4008e5:	xor    %eax,%eax
  4008e7:	pop    %rbx
  4008e8:	pop    %rbp
  4008e9:	retq   
  4008ea:	lea    0x867(%rip),%rdi        # 401158 <__dso_handle+0x50>
  4008f1:	xor    %eax,%eax
  4008f3:	callq  400a80 <ck_error>
  4008f8:	lea    0x8c9(%rip),%rdi        # 4011c8 <__dso_handle+0xc0>
  4008ff:	xor    %eax,%eax
  400901:	callq  400a80 <ck_error>
  400906:	lea    0x883(%rip),%rdi        # 401190 <__dso_handle+0x88>
  40090d:	xor    %eax,%eax
  40090f:	callq  400a80 <ck_error>
  400914:	nopw   %cs:0x0(%rax,%rax,1)
  40091e:	xchg   %ax,%ax

0000000000400920 <_start>:
  400920:	xor    %ebp,%ebp
  400922:	mov    %rdx,%r9
  400925:	pop    %rsi
  400926:	mov    %rsp,%rdx
  400929:	and    $0xfffffffffffffff0,%rsp
  40092d:	push   %rax
  40092e:	push   %rsp
  40092f:	mov    $0x4010f0,%r8
  400936:	mov    $0x401080,%rcx
  40093d:	mov    $0x400860,%rdi
  400944:	callq  *0x20169e(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  40094a:	hlt    
  40094b:	nopl   0x0(%rax,%rax,1)

0000000000400950 <deregister_tm_clones>:
  400950:	mov    $0x602087,%eax
  400955:	push   %rbp
  400956:	sub    $0x602080,%rax
  40095c:	cmp    $0xe,%rax
  400960:	mov    %rsp,%rbp
  400963:	jbe    400980 <deregister_tm_clones+0x30>
  400965:	mov    $0x0,%eax
  40096a:	test   %rax,%rax
  40096d:	je     400980 <deregister_tm_clones+0x30>
  40096f:	pop    %rbp
  400970:	mov    $0x602080,%edi
  400975:	jmpq   *%rax
  400977:	nopw   0x0(%rax,%rax,1)
  400980:	pop    %rbp
  400981:	retq   
  400982:	nopl   0x0(%rax)
  400986:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400990 <register_tm_clones>:
  400990:	mov    $0x602080,%esi
  400995:	push   %rbp
  400996:	sub    $0x602080,%rsi
  40099d:	sar    $0x3,%rsi
  4009a1:	mov    %rsp,%rbp
  4009a4:	mov    %rsi,%rax
  4009a7:	shr    $0x3f,%rax
  4009ab:	add    %rax,%rsi
  4009ae:	sar    %rsi
  4009b1:	je     4009c8 <register_tm_clones+0x38>
  4009b3:	mov    $0x0,%eax
  4009b8:	test   %rax,%rax
  4009bb:	je     4009c8 <register_tm_clones+0x38>
  4009bd:	pop    %rbp
  4009be:	mov    $0x602080,%edi
  4009c3:	jmpq   *%rax
  4009c5:	nopl   (%rax)
  4009c8:	pop    %rbp
  4009c9:	retq   
  4009ca:	nopw   0x0(%rax,%rax,1)

00000000004009d0 <__do_global_dtors_aux>:
  4009d0:	cmpb   $0x0,0x2016a9(%rip)        # 602080 <__TMC_END__>
  4009d7:	jne    4009ea <__do_global_dtors_aux+0x1a>
  4009d9:	push   %rbp
  4009da:	mov    %rsp,%rbp
  4009dd:	callq  400950 <deregister_tm_clones>
  4009e2:	pop    %rbp
  4009e3:	movb   $0x1,0x201696(%rip)        # 602080 <__TMC_END__>
  4009ea:	repz retq 
  4009ec:	nopl   0x0(%rax)

00000000004009f0 <frame_dummy>:
  4009f0:	mov    $0x601e00,%edi
  4009f5:	cmpq   $0x0,(%rdi)
  4009f9:	jne    400a00 <frame_dummy+0x10>
  4009fb:	jmp    400990 <register_tm_clones>
  4009fd:	nopl   (%rax)
  400a00:	mov    $0x0,%eax
  400a05:	test   %rax,%rax
  400a08:	je     4009fb <frame_dummy+0xb>
  400a0a:	push   %rbp
  400a0b:	mov    %rsp,%rbp
  400a0e:	callq  *%rax
  400a10:	pop    %rbp
  400a11:	jmpq   400990 <register_tm_clones>
  400a16:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a20 <aff_iterate.constprop.1>:
  400a20:	push   %rbx
  400a21:	add    $0xffffffffffffff80,%rsp
  400a25:	mov    0x20167d(%rip),%esi        # 6020a8 <a>
  400a2b:	lock xadd %esi,0x201679(%rip)        # 6020ac <a+0x4>
  400a33:	xor    %eax,%eax
  400a35:	mov    %rsp,%rdi
  400a38:	mov    $0x10,%ecx
  400a3d:	rep stos %rax,%es:(%rdi)
  400a40:	mov    %esi,%ecx
  400a42:	mov    $0x1,%eax
  400a47:	mov    $0xba,%edi
  400a4c:	and    $0x3,%ecx
  400a4f:	shl    %cl,%rax
  400a52:	mov    %rax,(%rsp)
  400a56:	xor    %eax,%eax
  400a58:	callq  4007e0 <syscall@plt>
  400a5d:	mov    %rsp,%rdx
  400a60:	mov    $0x80,%esi
  400a65:	mov    %eax,%edi
  400a67:	callq  4007b0 <sched_setaffinity@plt>
  400a6c:	sub    $0xffffffffffffff80,%rsp
  400a70:	pop    %rbx
  400a71:	retq   
  400a72:	nopl   0x0(%rax)
  400a76:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a80 <ck_error>:
  400a80:	sub    $0xd8,%rsp
  400a87:	test   %al,%al
  400a89:	mov    %rsi,0x28(%rsp)
  400a8e:	mov    %rdx,0x30(%rsp)
  400a93:	mov    %rcx,0x38(%rsp)
  400a98:	mov    %r8,0x40(%rsp)
  400a9d:	mov    %r9,0x48(%rsp)
  400aa2:	je     400adb <ck_error+0x5b>
  400aa4:	movaps %xmm0,0x50(%rsp)
  400aa9:	movaps %xmm1,0x60(%rsp)
  400aae:	movaps %xmm2,0x70(%rsp)
  400ab3:	movaps %xmm3,0x80(%rsp)
  400abb:	movaps %xmm4,0x90(%rsp)
  400ac3:	movaps %xmm5,0xa0(%rsp)
  400acb:	movaps %xmm6,0xb0(%rsp)
  400ad3:	movaps %xmm7,0xc0(%rsp)
  400adb:	lea    0xe0(%rsp),%rax
  400ae3:	mov    %rdi,%rsi
  400ae6:	lea    0x8(%rsp),%rdx
  400aeb:	mov    %rax,0x10(%rsp)
  400af0:	lea    0x20(%rsp),%rax
  400af5:	movl   $0x8,0x8(%rsp)
  400afd:	movl   $0x30,0xc(%rsp)
  400b05:	mov    %rax,0x18(%rsp)
  400b0a:	mov    0x2014e7(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400b11:	mov    (%rax),%rdi
  400b14:	callq  400830 <vfprintf@plt>
  400b19:	mov    $0x1,%edi
  400b1e:	callq  400840 <exit@plt>
  400b23:	nopl   (%rax)
  400b26:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b30 <thread_recursive>:
  400b30:	push   %rbx
  400b31:	mov    $0x1,%ebx
  400b36:	lock xadd %ebx,0x20153e(%rip)        # 60207c <tid>
  400b3e:	callq  400a20 <aff_iterate.constprop.1>
  400b43:	test   %eax,%eax
  400b45:	jne    400d99 <thread_recursive+0x269>
  400b4b:	mov    $0xf4240,%edi
  400b50:	lea    0x201531(%rip),%rcx        # 602088 <r_lock>
  400b57:	xor    %esi,%esi
  400b59:	jmp    400b87 <thread_recursive+0x57>
  400b5b:	nopl   0x0(%rax,%rax,1)
  400b60:	mov    %esi,%eax
  400b62:	lock cmpxchg %ebx,0x20151e(%rip)        # 602088 <r_lock>
  400b6a:	sete   %al
  400b6d:	test   %al,%al
  400b6f:	je     400b85 <thread_recursive+0x55>
  400b71:	mov    0x201515(%rip),%eax        # 60208c <r_lock+0x4>
  400b77:	test   %eax,%eax
  400b79:	je     400d94 <thread_recursive+0x264>
  400b7f:	movl   $0x0,(%rcx)
  400b85:	pause  
  400b87:	mov    (%rcx),%eax
  400b89:	cmp    %eax,%ebx
  400b8b:	jne    400b60 <thread_recursive+0x30>
  400b8d:	addl   $0x1,0x2014fc(%rip)        # 602090 <r_lock+0x8>
  400b94:	mov    (%rcx),%eax
  400b96:	cmp    %eax,%ebx
  400b98:	jne    400ba2 <thread_recursive+0x72>
  400b9a:	jmp    400bcc <thread_recursive+0x9c>
  400b9c:	nopl   0x0(%rax)
  400ba0:	pause  
  400ba2:	mov    %esi,%eax
  400ba4:	lock cmpxchg %ebx,0x2014dc(%rip)        # 602088 <r_lock>
  400bac:	sete   %al
  400baf:	test   %al,%al
  400bb1:	je     400ba0 <thread_recursive+0x70>
  400bb3:	mov    0x2014d3(%rip),%eax        # 60208c <r_lock+0x4>
  400bb9:	test   %eax,%eax
  400bbb:	je     400bcc <thread_recursive+0x9c>
  400bbd:	nopl   (%rax)
  400bc0:	pause  
  400bc2:	mov    0x2014c4(%rip),%eax        # 60208c <r_lock+0x4>
  400bc8:	test   %eax,%eax
  400bca:	jne    400bc0 <thread_recursive+0x90>
  400bcc:	addl   $0x1,0x2014bd(%rip)        # 602090 <r_lock+0x8>
  400bd3:	mov    (%rcx),%eax
  400bd5:	cmp    %eax,%ebx
  400bd7:	jne    400be2 <thread_recursive+0xb2>
  400bd9:	jmp    400c0c <thread_recursive+0xdc>
  400bdb:	nopl   0x0(%rax,%rax,1)
  400be0:	pause  
  400be2:	mov    %esi,%eax
  400be4:	lock cmpxchg %ebx,0x20149c(%rip)        # 602088 <r_lock>
  400bec:	sete   %al
  400bef:	test   %al,%al
  400bf1:	je     400be0 <thread_recursive+0xb0>
  400bf3:	mov    0x201493(%rip),%eax        # 60208c <r_lock+0x4>
  400bf9:	test   %eax,%eax
  400bfb:	je     400c0c <thread_recursive+0xdc>
  400bfd:	nopl   (%rax)
  400c00:	pause  
  400c02:	mov    0x201484(%rip),%eax        # 60208c <r_lock+0x4>
  400c08:	test   %eax,%eax
  400c0a:	jne    400c00 <thread_recursive+0xd0>
  400c0c:	addl   $0x1,0x20147d(%rip)        # 602090 <r_lock+0x8>
  400c13:	mov    (%rcx),%eax
  400c15:	cmp    %eax,%ebx
  400c17:	jne    400c22 <thread_recursive+0xf2>
  400c19:	jmp    400c4c <thread_recursive+0x11c>
  400c1b:	nopl   0x0(%rax,%rax,1)
  400c20:	pause  
  400c22:	mov    %esi,%eax
  400c24:	lock cmpxchg %ebx,0x20145c(%rip)        # 602088 <r_lock>
  400c2c:	sete   %al
  400c2f:	test   %al,%al
  400c31:	je     400c20 <thread_recursive+0xf0>
  400c33:	mov    0x201453(%rip),%eax        # 60208c <r_lock+0x4>
  400c39:	test   %eax,%eax
  400c3b:	je     400c4c <thread_recursive+0x11c>
  400c3d:	nopl   (%rax)
  400c40:	pause  
  400c42:	mov    0x201444(%rip),%eax        # 60208c <r_lock+0x4>
  400c48:	test   %eax,%eax
  400c4a:	jne    400c40 <thread_recursive+0x110>
  400c4c:	addl   $0x1,0x20143d(%rip)        # 602090 <r_lock+0x8>
  400c53:	mov    0x20144b(%rip),%edx        # 6020a4 <locked>
  400c59:	test   %edx,%edx
  400c5b:	jne    400de8 <thread_recursive+0x2b8>
  400c61:	lock incl 0x20143c(%rip)        # 6020a4 <locked>
  400c68:	lock incl 0x201435(%rip)        # 6020a4 <locked>
  400c6f:	lock incl 0x20142e(%rip)        # 6020a4 <locked>
  400c76:	lock incl 0x201427(%rip)        # 6020a4 <locked>
  400c7d:	lock incl 0x201420(%rip)        # 6020a4 <locked>
  400c84:	lock incl 0x201419(%rip)        # 6020a4 <locked>
  400c8b:	lock incl 0x201412(%rip)        # 6020a4 <locked>
  400c92:	lock incl 0x20140b(%rip)        # 6020a4 <locked>
  400c99:	mov    0x201405(%rip),%edx        # 6020a4 <locked>
  400c9f:	cmp    $0x8,%edx
  400ca2:	jne    400dd5 <thread_recursive+0x2a5>
  400ca8:	lock decl 0x2013f5(%rip)        # 6020a4 <locked>
  400caf:	lock decl 0x2013ee(%rip)        # 6020a4 <locked>
  400cb6:	lock decl 0x2013e7(%rip)        # 6020a4 <locked>
  400cbd:	lock decl 0x2013e0(%rip)        # 6020a4 <locked>
  400cc4:	lock decl 0x2013d9(%rip)        # 6020a4 <locked>
  400ccb:	lock decl 0x2013d2(%rip)        # 6020a4 <locked>
  400cd2:	lock decl 0x2013cb(%rip)        # 6020a4 <locked>
  400cd9:	lock decl 0x2013c4(%rip)        # 6020a4 <locked>
  400ce0:	mov    0x2013be(%rip),%edx        # 6020a4 <locked>
  400ce6:	test   %edx,%edx
  400ce8:	jne    400dc2 <thread_recursive+0x292>
  400cee:	mov    0x20139c(%rip),%eax        # 602090 <r_lock+0x8>
  400cf4:	sub    $0x1,%eax
  400cf7:	test   %eax,%eax
  400cf9:	mov    %eax,0x201391(%rip)        # 602090 <r_lock+0x8>
  400cff:	jne    400d0d <thread_recursive+0x1dd>
  400d01:	movl   $0x0,(%rcx)
  400d07:	mov    0x201383(%rip),%eax        # 602090 <r_lock+0x8>
  400d0d:	sub    $0x1,%eax
  400d10:	test   %eax,%eax
  400d12:	mov    %eax,0x201378(%rip)        # 602090 <r_lock+0x8>
  400d18:	jne    400d26 <thread_recursive+0x1f6>
  400d1a:	movl   $0x0,(%rcx)
  400d20:	mov    0x20136a(%rip),%eax        # 602090 <r_lock+0x8>
  400d26:	sub    $0x1,%eax
  400d29:	test   %eax,%eax
  400d2b:	mov    %eax,0x20135f(%rip)        # 602090 <r_lock+0x8>
  400d31:	jne    400d3f <thread_recursive+0x20f>
  400d33:	movl   $0x0,(%rcx)
  400d39:	mov    0x201351(%rip),%eax        # 602090 <r_lock+0x8>
  400d3f:	sub    $0x1,%eax
  400d42:	test   %eax,%eax
  400d44:	mov    %eax,0x201346(%rip)        # 602090 <r_lock+0x8>
  400d4a:	jne    400d5a <thread_recursive+0x22a>
  400d4c:	movl   $0x0,(%rcx)
  400d52:	jmp    400d5a <thread_recursive+0x22a>
  400d54:	nopl   0x0(%rax)
  400d58:	pause  
  400d5a:	mov    (%rcx),%eax
  400d5c:	test   %eax,%eax
  400d5e:	jne    400d58 <thread_recursive+0x228>
  400d60:	lock incl 0x201325(%rip)        # 60208c <r_lock+0x4>
  400d67:	mov    (%rcx),%eax
  400d69:	test   %eax,%eax
  400d6b:	je     400d76 <thread_recursive+0x246>
  400d6d:	lock decl 0x201318(%rip)        # 60208c <r_lock+0x4>
  400d74:	jmp    400d5a <thread_recursive+0x22a>
  400d76:	mov    0x201328(%rip),%edx        # 6020a4 <locked>
  400d7c:	test   %edx,%edx
  400d7e:	jne    400daf <thread_recursive+0x27f>
  400d80:	lock decl 0x201305(%rip)        # 60208c <r_lock+0x4>
  400d87:	sub    $0x1,%edi
  400d8a:	jne    400b87 <thread_recursive+0x57>
  400d90:	xor    %eax,%eax
  400d92:	pop    %rbx
  400d93:	retq   
  400d94:	jmpq   400b8d <thread_recursive+0x5d>
  400d99:	lea    0x370(%rip),%rdi        # 401110 <__dso_handle+0x8>
  400da0:	callq  400810 <perror@plt>
  400da5:	mov    $0x1,%edi
  400daa:	callq  400840 <exit@plt>
  400daf:	lea    0x472(%rip),%rdi        # 401228 <__dso_handle+0x120>
  400db6:	mov    $0x75,%esi
  400dbb:	xor    %eax,%eax
  400dbd:	callq  400a80 <ck_error>
  400dc2:	lea    0x42f(%rip),%rdi        # 4011f8 <__dso_handle+0xf0>
  400dc9:	mov    $0x69,%esi
  400dce:	xor    %eax,%eax
  400dd0:	callq  400a80 <ck_error>
  400dd5:	lea    0x434(%rip),%rdi        # 401210 <__dso_handle+0x108>
  400ddc:	mov    $0x5b,%esi
  400de1:	xor    %eax,%eax
  400de3:	callq  400a80 <ck_error>
  400de8:	lea    0x409(%rip),%rdi        # 4011f8 <__dso_handle+0xf0>
  400def:	mov    $0x4d,%esi
  400df4:	xor    %eax,%eax
  400df6:	callq  400a80 <ck_error>
  400dfb:	nopl   0x0(%rax,%rax,1)

0000000000400e00 <thread>:
  400e00:	sub    $0x8,%rsp
  400e04:	callq  400a20 <aff_iterate.constprop.1>
  400e09:	test   %eax,%eax
  400e0b:	jne    400f8b <thread+0x18b>
  400e11:	mov    $0xf4240,%esi
  400e16:	mov    $0x1,%ecx
  400e1b:	jmp    400e22 <thread+0x22>
  400e1d:	nopl   (%rax)
  400e20:	pause  
  400e22:	mov    %ecx,%eax
  400e24:	xchg   %eax,0x20126e(%rip)        # 602098 <lock>
  400e2a:	test   %eax,%eax
  400e2c:	jne    400e20 <thread+0x20>
  400e2e:	mov    0x201268(%rip),%eax        # 60209c <lock+0x4>
  400e34:	test   %eax,%eax
  400e36:	je     400e4c <thread+0x4c>
  400e38:	nopl   0x0(%rax,%rax,1)
  400e40:	pause  
  400e42:	mov    0x201254(%rip),%eax        # 60209c <lock+0x4>
  400e48:	test   %eax,%eax
  400e4a:	jne    400e40 <thread+0x40>
  400e4c:	mov    0x201252(%rip),%edx        # 6020a4 <locked>
  400e52:	test   %edx,%edx
  400e54:	jne    400f78 <thread+0x178>
  400e5a:	lock incl 0x201243(%rip)        # 6020a4 <locked>
  400e61:	lock incl 0x20123c(%rip)        # 6020a4 <locked>
  400e68:	lock incl 0x201235(%rip)        # 6020a4 <locked>
  400e6f:	lock incl 0x20122e(%rip)        # 6020a4 <locked>
  400e76:	lock incl 0x201227(%rip)        # 6020a4 <locked>
  400e7d:	lock incl 0x201220(%rip)        # 6020a4 <locked>
  400e84:	lock incl 0x201219(%rip)        # 6020a4 <locked>
  400e8b:	lock incl 0x201212(%rip)        # 6020a4 <locked>
  400e92:	mov    0x20120c(%rip),%edx        # 6020a4 <locked>
  400e98:	cmp    $0x8,%edx
  400e9b:	jne    400f65 <thread+0x165>
  400ea1:	lock decl 0x2011fc(%rip)        # 6020a4 <locked>
  400ea8:	lock decl 0x2011f5(%rip)        # 6020a4 <locked>
  400eaf:	lock decl 0x2011ee(%rip)        # 6020a4 <locked>
  400eb6:	lock decl 0x2011e7(%rip)        # 6020a4 <locked>
  400ebd:	lock decl 0x2011e0(%rip)        # 6020a4 <locked>
  400ec4:	lock decl 0x2011d9(%rip)        # 6020a4 <locked>
  400ecb:	lock decl 0x2011d2(%rip)        # 6020a4 <locked>
  400ed2:	lock decl 0x2011cb(%rip)        # 6020a4 <locked>
  400ed9:	mov    0x2011c5(%rip),%edx        # 6020a4 <locked>
  400edf:	test   %edx,%edx
  400ee1:	jne    400f52 <thread+0x152>
  400ee3:	lea    0x2011ae(%rip),%rdx        # 602098 <lock>
  400eea:	movl   $0x0,0x2011a4(%rip)        # 602098 <lock>
  400ef4:	jmp    400f02 <thread+0x102>
  400ef6:	nopw   %cs:0x0(%rax,%rax,1)
  400f00:	pause  
  400f02:	mov    (%rdx),%eax
  400f04:	test   %eax,%eax
  400f06:	jne    400f00 <thread+0x100>
  400f08:	lock incl 0x20118d(%rip)        # 60209c <lock+0x4>
  400f0f:	mov    (%rdx),%eax
  400f11:	test   %eax,%eax
  400f13:	je     400f1e <thread+0x11e>
  400f15:	lock decl 0x201180(%rip)        # 60209c <lock+0x4>
  400f1c:	jmp    400f02 <thread+0x102>
  400f1e:	mov    0x201180(%rip),%edx        # 6020a4 <locked>
  400f24:	test   %edx,%edx
  400f26:	jne    400f3f <thread+0x13f>
  400f28:	lock decl 0x20116d(%rip)        # 60209c <lock+0x4>
  400f2f:	sub    $0x1,%esi
  400f32:	jne    400e22 <thread+0x22>
  400f38:	xor    %eax,%eax
  400f3a:	add    $0x8,%rsp
  400f3e:	retq   
  400f3f:	lea    0x2e2(%rip),%rdi        # 401228 <__dso_handle+0x120>
  400f46:	mov    $0x185,%esi
  400f4b:	xor    %eax,%eax
  400f4d:	callq  400a80 <ck_error>
  400f52:	lea    0x29f(%rip),%rdi        # 4011f8 <__dso_handle+0xf0>
  400f59:	mov    $0x17c,%esi
  400f5e:	xor    %eax,%eax
  400f60:	callq  400a80 <ck_error>
  400f65:	lea    0x2a4(%rip),%rdi        # 401210 <__dso_handle+0x108>
  400f6c:	mov    $0x16e,%esi
  400f71:	xor    %eax,%eax
  400f73:	callq  400a80 <ck_error>
  400f78:	lea    0x279(%rip),%rdi        # 4011f8 <__dso_handle+0xf0>
  400f7f:	mov    $0x160,%esi
  400f84:	xor    %eax,%eax
  400f86:	callq  400a80 <ck_error>
  400f8b:	lea    0x17e(%rip),%rdi        # 401110 <__dso_handle+0x8>
  400f92:	callq  400810 <perror@plt>
  400f97:	mov    $0x1,%edi
  400f9c:	callq  400840 <exit@plt>
  400fa1:	nopl   0x0(%rax,%rax,1)
  400fa6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400fb0 <rwlock_test>:
  400fb0:	push   %r14
  400fb2:	push   %r13
  400fb4:	mov    %rsi,%r14
  400fb7:	mov    0x20103a(%rip),%r13        # 601ff8 <_DYNAMIC+0x1f0>
  400fbe:	push   %r12
  400fc0:	mov    %rdi,%r12
  400fc3:	push   %rbp
  400fc4:	push   %rbx
  400fc5:	lea    0x274(%rip),%rsi        # 401240 <__dso_handle+0x138>
  400fcc:	xor    %eax,%eax
  400fce:	xor    %ebx,%ebx
  400fd0:	mov    %r12,%rbp
  400fd3:	mov    0x0(%r13),%rdi
  400fd7:	callq  4007d0 <fprintf@plt>
  400fdc:	mov    0x2010be(%rip),%edx        # 6020a0 <nthr>
  400fe2:	test   %edx,%edx
  400fe4:	jle    401012 <rwlock_test+0x62>
  400fe6:	nopw   %cs:0x0(%rax,%rax,1)
  400ff0:	xor    %ecx,%ecx
  400ff2:	xor    %esi,%esi
  400ff4:	mov    %r14,%rdx
  400ff7:	mov    %rbp,%rdi
  400ffa:	callq  4007a0 <pthread_create@plt>
  400fff:	test   %eax,%eax
  401001:	jne    40106c <rwlock_test+0xbc>
  401003:	add    $0x1,%ebx
  401006:	add    $0x8,%rbp
  40100a:	cmp    %ebx,0x201090(%rip)        # 6020a0 <nthr>
  401010:	jg     400ff0 <rwlock_test+0x40>
  401012:	mov    0x0(%r13),%rsi
  401016:	mov    $0x2e,%edi
  40101b:	mov    $0x1,%ebx
  401020:	callq  4007c0 <fputc@plt>
  401025:	mov    0x201075(%rip),%eax        # 6020a0 <nthr>
  40102b:	test   %eax,%eax
  40102d:	jle    40104a <rwlock_test+0x9a>
  40102f:	nop
  401030:	mov    -0x8(%r12,%rbx,8),%rdi
  401035:	xor    %esi,%esi
  401037:	callq  400820 <pthread_join@plt>
  40103c:	mov    %ebx,%eax
  40103e:	add    $0x1,%rbx
  401042:	cmp    0x201058(%rip),%eax        # 6020a0 <nthr>
  401048:	jl     401030 <rwlock_test+0x80>
  40104a:	pop    %rbx
  40104b:	mov    0x0(%r13),%rcx
  40104f:	lea    0x203(%rip),%rdi        # 401259 <__dso_handle+0x151>
  401056:	mov    $0xe,%edx
  40105b:	pop    %rbp
  40105c:	pop    %r12
  40105e:	pop    %r13
  401060:	pop    %r14
  401062:	mov    $0x1,%esi
  401067:	jmpq   400850 <fwrite@plt>
  40106c:	lea    0xbd(%rip),%rdi        # 401130 <__dso_handle+0x28>
  401073:	mov    %ebx,%esi
  401075:	xor    %eax,%eax
  401077:	callq  400a80 <ck_error>
  40107c:	nopl   0x0(%rax)

0000000000401080 <__libc_csu_init>:
  401080:	push   %r15
  401082:	push   %r14
  401084:	mov    %edi,%r15d
  401087:	push   %r13
  401089:	push   %r12
  40108b:	lea    0x200d5e(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  401092:	push   %rbp
  401093:	lea    0x200d5e(%rip),%rbp        # 601df8 <__init_array_end>
  40109a:	push   %rbx
  40109b:	mov    %rsi,%r14
  40109e:	mov    %rdx,%r13
  4010a1:	sub    %r12,%rbp
  4010a4:	sub    $0x8,%rsp
  4010a8:	sar    $0x3,%rbp
  4010ac:	callq  400770 <_init>
  4010b1:	test   %rbp,%rbp
  4010b4:	je     4010d6 <__libc_csu_init+0x56>
  4010b6:	xor    %ebx,%ebx
  4010b8:	nopl   0x0(%rax,%rax,1)
  4010c0:	mov    %r13,%rdx
  4010c3:	mov    %r14,%rsi
  4010c6:	mov    %r15d,%edi
  4010c9:	callq  *(%r12,%rbx,8)
  4010cd:	add    $0x1,%rbx
  4010d1:	cmp    %rbx,%rbp
  4010d4:	jne    4010c0 <__libc_csu_init+0x40>
  4010d6:	add    $0x8,%rsp
  4010da:	pop    %rbx
  4010db:	pop    %rbp
  4010dc:	pop    %r12
  4010de:	pop    %r13
  4010e0:	pop    %r14
  4010e2:	pop    %r15
  4010e4:	retq   
  4010e5:	nop
  4010e6:	nopw   %cs:0x0(%rax,%rax,1)

00000000004010f0 <__libc_csu_fini>:
  4010f0:	repz retq 

Disassembly of section .fini:

00000000004010f4 <_fini>:
  4010f4:	sub    $0x8,%rsp
  4010f8:	add    $0x8,%rsp
  4010fc:	retq   
