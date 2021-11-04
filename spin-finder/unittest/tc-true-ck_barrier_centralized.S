// TC_OUT ck_barrier_centralized,0x400c08,0x400c0e,0x0(%rdx)
// TC_OUT thread,0x400b40,0x400b4e,0x0(0x6020a0),0x0(0x6028c0)
barrier_centralized:     file format elf64-x86-64


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
  400780:	cmp    $0x2,%edi
  400783:	push   %r14
  400785:	push   %r13
  400787:	push   %r12
  400789:	push   %rbp
  40078a:	push   %rbx
  40078b:	jle    4008fb <main+0x17b>
  400791:	mov    0x8(%rsi),%rdi
  400795:	mov    %rsi,%rbx
  400798:	mov    $0xa,%edx
  40079d:	xor    %esi,%esi
  40079f:	callq  400720 <strtol@plt>
  4007a4:	test   %eax,%eax
  4007a6:	mov    %eax,0x202114(%rip)        # 6028c0 <nthr>
  4007ac:	jle    4008ed <main+0x16d>
  4007b2:	cltq   
  4007b4:	lea    0x0(,%rax,8),%rdi
  4007bc:	callq  400730 <malloc@plt>
  4007c1:	test   %rax,%rax
  4007c4:	mov    %rax,%r12
  4007c7:	je     4008df <main+0x15f>
  4007cd:	mov    0x10(%rbx),%rdi
  4007d1:	xor    %esi,%esi
  4007d3:	mov    $0xa,%edx
  4007d8:	xor    %ebx,%ebx
  4007da:	mov    %r12,%rbp
  4007dd:	lea    0x2dc(%rip),%r14        # 400ac0 <thread>
  4007e4:	callq  400720 <strtol@plt>
  4007e9:	mov    0x201808(%rip),%r13        # 601ff8 <_DYNAMIC+0x1f0>
  4007f0:	lea    0x4e3(%rip),%rdi        # 400cda <__dso_handle+0x22>
  4007f7:	mov    $0x1d,%edx
  4007fc:	mov    $0x1,%esi
  400801:	mov    %eax,0x2020c1(%rip)        # 6028c8 <a>
  400807:	mov    0x0(%r13),%rcx
  40080b:	callq  400770 <fwrite@plt>
  400810:	mov    0x2020aa(%rip),%edx        # 6028c0 <nthr>
  400816:	test   %edx,%edx
  400818:	jle    400846 <main+0xc6>
  40081a:	nopw   0x0(%rax,%rax,1)
  400820:	xor    %ecx,%ecx
  400822:	xor    %esi,%esi
  400824:	mov    %r14,%rdx
  400827:	mov    %rbp,%rdi
  40082a:	callq  4006f0 <pthread_create@plt>
  40082f:	test   %eax,%eax
  400831:	jne    4008cf <main+0x14f>
  400837:	add    $0x1,%ebx
  40083a:	add    $0x8,%rbp
  40083e:	cmp    %ebx,0x20207c(%rip)        # 6028c0 <nthr>
  400844:	jg     400820 <main+0xa0>
  400846:	mov    0x0(%r13),%rcx
  40084a:	lea    0x4a7(%rip),%rdi        # 400cf8 <__dso_handle+0x40>
  400851:	mov    $0x5,%edx
  400856:	mov    $0x1,%esi
  40085b:	mov    $0x1,%ebx
  400860:	callq  400770 <fwrite@plt>
  400865:	mov    0x0(%r13),%rcx
  400869:	lea    0x540(%rip),%rdi        # 400db0 <__dso_handle+0xf8>
  400870:	mov    $0x37,%edx
  400875:	mov    $0x1,%esi
  40087a:	callq  400770 <fwrite@plt>
  40087f:	mov    0x20203b(%rip),%eax        # 6028c0 <nthr>
  400885:	test   %eax,%eax
  400887:	jle    4008aa <main+0x12a>
  400889:	nopl   0x0(%rax)
  400890:	mov    -0x8(%r12,%rbx,8),%rdi
  400895:	xor    %esi,%esi
  400897:	callq  400740 <pthread_join@plt>
  40089c:	mov    %ebx,%eax
  40089e:	add    $0x1,%rbx
  4008a2:	cmp    %eax,0x202018(%rip)        # 6028c0 <nthr>
  4008a8:	jg     400890 <main+0x110>
  4008aa:	mov    0x0(%r13),%rcx
  4008ae:	lea    0x449(%rip),%rdi        # 400cfe <__dso_handle+0x46>
  4008b5:	mov    $0xe,%edx
  4008ba:	mov    $0x1,%esi
  4008bf:	callq  400770 <fwrite@plt>
  4008c4:	pop    %rbx
  4008c5:	xor    %eax,%eax
  4008c7:	pop    %rbp
  4008c8:	pop    %r12
  4008ca:	pop    %r13
  4008cc:	pop    %r14
  4008ce:	retq   
  4008cf:	lea    0x512(%rip),%rdi        # 400de8 <__dso_handle+0x130>
  4008d6:	mov    %ebx,%esi
  4008d8:	xor    %eax,%eax
  4008da:	callq  400a10 <ck_error>
  4008df:	lea    0x49a(%rip),%rdi        # 400d80 <__dso_handle+0xc8>
  4008e6:	xor    %eax,%eax
  4008e8:	callq  400a10 <ck_error>
  4008ed:	lea    0x454(%rip),%rdi        # 400d48 <__dso_handle+0x90>
  4008f4:	xor    %eax,%eax
  4008f6:	callq  400a10 <ck_error>
  4008fb:	lea    0x40e(%rip),%rdi        # 400d10 <__dso_handle+0x58>
  400902:	xor    %eax,%eax
  400904:	callq  400a10 <ck_error>
  400909:	nopl   0x0(%rax)

0000000000400910 <_start>:
  400910:	xor    %ebp,%ebp
  400912:	mov    %rdx,%r9
  400915:	pop    %rsi
  400916:	mov    %rsp,%rdx
  400919:	and    $0xfffffffffffffff0,%rsp
  40091d:	push   %rax
  40091e:	push   %rsp
  40091f:	mov    $0x400ca0,%r8
  400926:	mov    $0x400c30,%rcx
  40092d:	mov    $0x400780,%rdi
  400934:	callq  *0x2016ae(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  40093a:	hlt    
  40093b:	nopl   0x0(%rax,%rax,1)

0000000000400940 <deregister_tm_clones>:
  400940:	mov    $0x60206f,%eax
  400945:	push   %rbp
  400946:	sub    $0x602068,%rax
  40094c:	cmp    $0xe,%rax
  400950:	mov    %rsp,%rbp
  400953:	jbe    400970 <deregister_tm_clones+0x30>
  400955:	mov    $0x0,%eax
  40095a:	test   %rax,%rax
  40095d:	je     400970 <deregister_tm_clones+0x30>
  40095f:	pop    %rbp
  400960:	mov    $0x602068,%edi
  400965:	jmpq   *%rax
  400967:	nopw   0x0(%rax,%rax,1)
  400970:	pop    %rbp
  400971:	retq   
  400972:	nopl   0x0(%rax)
  400976:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400980 <register_tm_clones>:
  400980:	mov    $0x602068,%esi
  400985:	push   %rbp
  400986:	sub    $0x602068,%rsi
  40098d:	sar    $0x3,%rsi
  400991:	mov    %rsp,%rbp
  400994:	mov    %rsi,%rax
  400997:	shr    $0x3f,%rax
  40099b:	add    %rax,%rsi
  40099e:	sar    %rsi
  4009a1:	je     4009b8 <register_tm_clones+0x38>
  4009a3:	mov    $0x0,%eax
  4009a8:	test   %rax,%rax
  4009ab:	je     4009b8 <register_tm_clones+0x38>
  4009ad:	pop    %rbp
  4009ae:	mov    $0x602068,%edi
  4009b3:	jmpq   *%rax
  4009b5:	nopl   (%rax)
  4009b8:	pop    %rbp
  4009b9:	retq   
  4009ba:	nopw   0x0(%rax,%rax,1)

00000000004009c0 <__do_global_dtors_aux>:
  4009c0:	cmpb   $0x0,0x2016b9(%rip)        # 602080 <completed.6917>
  4009c7:	jne    4009da <__do_global_dtors_aux+0x1a>
  4009c9:	push   %rbp
  4009ca:	mov    %rsp,%rbp
  4009cd:	callq  400940 <deregister_tm_clones>
  4009d2:	pop    %rbp
  4009d3:	movb   $0x1,0x2016a6(%rip)        # 602080 <completed.6917>
  4009da:	repz retq 
  4009dc:	nopl   0x0(%rax)

00000000004009e0 <frame_dummy>:
  4009e0:	mov    $0x601e00,%edi
  4009e5:	cmpq   $0x0,(%rdi)
  4009e9:	jne    4009f0 <frame_dummy+0x10>
  4009eb:	jmp    400980 <register_tm_clones>
  4009ed:	nopl   (%rax)
  4009f0:	mov    $0x0,%eax
  4009f5:	test   %rax,%rax
  4009f8:	je     4009eb <frame_dummy+0xb>
  4009fa:	push   %rbp
  4009fb:	mov    %rsp,%rbp
  4009fe:	callq  *%rax
  400a00:	pop    %rbp
  400a01:	jmpq   400980 <register_tm_clones>
  400a06:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a10 <ck_error>:
  400a10:	sub    $0xd8,%rsp
  400a17:	test   %al,%al
  400a19:	mov    %rsi,0x28(%rsp)
  400a1e:	mov    %rdx,0x30(%rsp)
  400a23:	mov    %rcx,0x38(%rsp)
  400a28:	mov    %r8,0x40(%rsp)
  400a2d:	mov    %r9,0x48(%rsp)
  400a32:	je     400a6b <ck_error+0x5b>
  400a34:	movaps %xmm0,0x50(%rsp)
  400a39:	movaps %xmm1,0x60(%rsp)
  400a3e:	movaps %xmm2,0x70(%rsp)
  400a43:	movaps %xmm3,0x80(%rsp)
  400a4b:	movaps %xmm4,0x90(%rsp)
  400a53:	movaps %xmm5,0xa0(%rsp)
  400a5b:	movaps %xmm6,0xb0(%rsp)
  400a63:	movaps %xmm7,0xc0(%rsp)
  400a6b:	lea    0xe0(%rsp),%rax
  400a73:	mov    %rdi,%rsi
  400a76:	lea    0x8(%rsp),%rdx
  400a7b:	mov    %rax,0x10(%rsp)
  400a80:	lea    0x20(%rsp),%rax
  400a85:	movl   $0x8,0x8(%rsp)
  400a8d:	movl   $0x30,0xc(%rsp)
  400a95:	mov    %rax,0x18(%rsp)
  400a9a:	mov    0x201557(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400aa1:	mov    (%rax),%rdi
  400aa4:	callq  400750 <vfprintf@plt>
  400aa9:	mov    $0x1,%edi
  400aae:	callq  400760 <exit@plt>
  400ab3:	nopl   (%rax)
  400ab6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400ac0 <thread>:
  400ac0:	push   %r15
  400ac2:	push   %r14
  400ac4:	push   %r13
  400ac6:	push   %r12
  400ac8:	push   %rbp
  400ac9:	push   %rbx
  400aca:	sub    $0x98,%rsp
  400ad1:	mov    0x201df1(%rip),%esi        # 6028c8 <a>
  400ad7:	movl   $0x0,(%rsp)
  400ade:	lock xadd %esi,0x201de6(%rip)        # 6028cc <a+0x4>
  400ae6:	lea    0x10(%rsp),%rbx
  400aeb:	xor    %eax,%eax
  400aed:	mov    $0x10,%ecx
  400af2:	and    $0x3,%esi
  400af5:	mov    %rbx,%rdi
  400af8:	rep stos %rax,%es:(%rdi)
  400afb:	mov    %esi,%ecx
  400afd:	mov    $0x1,%eax
  400b02:	mov    $0xba,%edi
  400b07:	shl    %cl,%rax
  400b0a:	mov    %rax,0x10(%rsp)
  400b0f:	xor    %eax,%eax
  400b11:	callq  400710 <syscall@plt>
  400b16:	mov    %rbx,%rdx
  400b19:	mov    $0x80,%esi
  400b1e:	mov    %eax,%edi
  400b20:	callq  400700 <sched_setaffinity@plt>
  400b25:	lock incl 0x201574(%rip)        # 6020a0 <barrier_wait>
  400b2c:	mov    0x20156e(%rip),%eax        # 6020a0 <barrier_wait>
  400b32:	cmp    %eax,0x201d88(%rip)        # 6028c0 <nthr>
  400b38:	je     400b50 <thread+0x90>
  400b3a:	nopw   0x0(%rax,%rax,1)
  400b40:	pause  
  400b42:	mov    0x201558(%rip),%eax        # 6020a0 <barrier_wait>
  400b48:	cmp    %eax,0x201d72(%rip)        # 6028c0 <nthr>
  400b4e:	jne    400b40 <thread+0x80>
  400b50:	lea    0x201569(%rip),%r12        # 6020c0 <counters>
  400b57:	lea    0x20154a(%rip),%rbx        # 6020a8 <barrier>
  400b5e:	xor    %r13d,%r13d
  400b61:	mov    %rsp,%rbp
  400b64:	nopl   0x0(%rax)
  400b68:	mov    %r13d,%r15d
  400b6b:	and    $0x1ff,%r15d
  400b72:	movslq %r15d,%rax
  400b75:	lea    (%r12,%rax,4),%r14
  400b79:	lock incl (%r14)
  400b7d:	mov    0x201d3d(%rip),%edx        # 6028c0 <nthr>
  400b83:	mov    %rbp,%rsi
  400b86:	mov    %rbx,%rdi
  400b89:	callq  400be0 <ck_barrier_centralized>
  400b8e:	mov    (%r14),%ecx
  400b91:	lea    0x1(%r13),%eax
  400b95:	mov    0x201d24(%rip),%r8d        # 6028c0 <nthr>
  400b9c:	sar    $0x9,%eax
  400b9f:	add    $0x1,%eax
  400ba2:	imul   %r8d,%eax
  400ba6:	cmp    %ecx,%eax
  400ba8:	jne    400bcb <thread+0x10b>
  400baa:	add    $0x2,%r13d
  400bae:	cmp    $0x4c4b40,%r13d
  400bb5:	jne    400b68 <thread+0xa8>
  400bb7:	add    $0x98,%rsp
  400bbe:	xor    %eax,%eax
  400bc0:	pop    %rbx
  400bc1:	pop    %rbp
  400bc2:	pop    %r12
  400bc4:	pop    %r13
  400bc6:	pop    %r14
  400bc8:	pop    %r15
  400bca:	retq   
  400bcb:	lea    0xee(%rip),%rdi        # 400cc0 <__dso_handle+0x8>
  400bd2:	mov    %r13d,%edx
  400bd5:	mov    %r15d,%esi
  400bd8:	xor    %eax,%eax
  400bda:	callq  400a10 <ck_error>
  400bdf:	nop

0000000000400be0 <ck_barrier_centralized>:
  400be0:	mov    (%rsi),%ecx
  400be2:	mov    $0x1,%eax
  400be7:	not    %ecx
  400be9:	mov    %ecx,(%rsi)
  400beb:	lock xadd %eax,(%rdi)
  400bef:	sub    $0x1,%edx
  400bf2:	cmp    %eax,%edx
  400bf4:	je     400c18 <ck_barrier_centralized+0x38>
  400bf6:	lea    0x4(%rdi),%rdx
  400bfa:	mov    0x4(%rdi),%eax
  400bfd:	cmp    %eax,%ecx
  400bff:	je     400c10 <ck_barrier_centralized+0x30>
  400c01:	nopl   0x0(%rax)
  400c08:	pause  
  400c0a:	mov    (%rdx),%eax
  400c0c:	cmp    %eax,%ecx
  400c0e:	jne    400c08 <ck_barrier_centralized+0x28>
  400c10:	retq   
  400c11:	nopl   0x0(%rax)
  400c18:	movl   $0x0,(%rdi)
  400c1e:	mfence 
  400c21:	mov    %ecx,0x4(%rdi)
  400c24:	retq   
  400c25:	nopw   %cs:0x0(%rax,%rax,1)
  400c2f:	nop

0000000000400c30 <__libc_csu_init>:
  400c30:	push   %r15
  400c32:	push   %r14
  400c34:	mov    %edi,%r15d
  400c37:	push   %r13
  400c39:	push   %r12
  400c3b:	lea    0x2011ae(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400c42:	push   %rbp
  400c43:	lea    0x2011ae(%rip),%rbp        # 601df8 <__init_array_end>
  400c4a:	push   %rbx
  400c4b:	mov    %rsi,%r14
  400c4e:	mov    %rdx,%r13
  400c51:	sub    %r12,%rbp
  400c54:	sub    $0x8,%rsp
  400c58:	sar    $0x3,%rbp
  400c5c:	callq  4006c8 <_init>
  400c61:	test   %rbp,%rbp
  400c64:	je     400c86 <__libc_csu_init+0x56>
  400c66:	xor    %ebx,%ebx
  400c68:	nopl   0x0(%rax,%rax,1)
  400c70:	mov    %r13,%rdx
  400c73:	mov    %r14,%rsi
  400c76:	mov    %r15d,%edi
  400c79:	callq  *(%r12,%rbx,8)
  400c7d:	add    $0x1,%rbx
  400c81:	cmp    %rbx,%rbp
  400c84:	jne    400c70 <__libc_csu_init+0x40>
  400c86:	add    $0x8,%rsp
  400c8a:	pop    %rbx
  400c8b:	pop    %rbp
  400c8c:	pop    %r12
  400c8e:	pop    %r13
  400c90:	pop    %r14
  400c92:	pop    %r15
  400c94:	retq   
  400c95:	nop
  400c96:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400ca0 <__libc_csu_fini>:
  400ca0:	repz retq 

Disassembly of section .fini:

0000000000400ca4 <_fini>:
  400ca4:	sub    $0x8,%rsp
  400ca8:	add    $0x8,%rsp
  400cac:	retq   
