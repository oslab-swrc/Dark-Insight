// TC_OUT thread,0x400c28,0x400c32,0x0(0x60208c)
// TC_OUT thread,0x400d40,0x400d4d,0x0(0x60208c)
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
  400860:	cmp    $0x3,%edi
  400863:	push   %r14
  400865:	push   %r13
  400867:	push   %r12
  400869:	push   %rbp
  40086a:	push   %rbx
  40086b:	jne    4009c7 <main+0x167>
  400871:	mov    0x8(%rsi),%rdi
  400875:	mov    %rsi,%rbx
  400878:	mov    $0xa,%edx
  40087d:	xor    %esi,%esi
  40087f:	callq  4007f0 <strtol@plt>
  400884:	test   %eax,%eax
  400886:	mov    %eax,0x201804(%rip)        # 602090 <nthr>
  40088c:	jle    4009b9 <main+0x159>
  400892:	cltq   
  400894:	lea    0x0(,%rax,8),%rdi
  40089c:	callq  400800 <malloc@plt>
  4008a1:	test   %rax,%rax
  4008a4:	mov    %rax,%r12
  4008a7:	je     4009ab <main+0x14b>
  4008ad:	mov    0x10(%rbx),%rdi
  4008b1:	xor    %esi,%esi
  4008b3:	mov    $0xa,%edx
  4008b8:	xor    %ebx,%ebx
  4008ba:	mov    %r12,%rbp
  4008bd:	lea    0x2cc(%rip),%r14        # 400b90 <thread>
  4008c4:	callq  4007f0 <strtol@plt>
  4008c9:	mov    0x201728(%rip),%r13        # 601ff8 <_DYNAMIC+0x1f0>
  4008d0:	lea    0x6e9(%rip),%rdx        # 400fc0 <__dso_handle+0x138>
  4008d7:	lea    0x6ea(%rip),%rsi        # 400fc8 <__dso_handle+0x140>
  4008de:	mov    %eax,0x2017b4(%rip)        # 602098 <a>
  4008e4:	xor    %eax,%eax
  4008e6:	mov    0x0(%r13),%rdi
  4008ea:	callq  4007d0 <fprintf@plt>
  4008ef:	mov    0x20179b(%rip),%edx        # 602090 <nthr>
  4008f5:	test   %edx,%edx
  4008f7:	jle    400926 <main+0xc6>
  4008f9:	nopl   0x0(%rax)
  400900:	xor    %ecx,%ecx
  400902:	xor    %esi,%esi
  400904:	mov    %r14,%rdx
  400907:	mov    %rbp,%rdi
  40090a:	callq  4007a0 <pthread_create@plt>
  40090f:	test   %eax,%eax
  400911:	jne    40099b <main+0x13b>
  400917:	add    $0x1,%ebx
  40091a:	add    $0x8,%rbp
  40091e:	cmp    0x20176c(%rip),%ebx        # 602090 <nthr>
  400924:	jl     400900 <main+0xa0>
  400926:	mov    0x0(%r13),%rsi
  40092a:	mov    $0x2e,%edi
  40092f:	mov    $0x1,%ebx
  400934:	callq  4007c0 <fputc@plt>
  400939:	mov    0x201751(%rip),%eax        # 602090 <nthr>
  40093f:	test   %eax,%eax
  400941:	jle    400962 <main+0x102>
  400943:	nopl   0x0(%rax,%rax,1)
  400948:	mov    -0x8(%r12,%rbx,8),%rdi
  40094d:	xor    %esi,%esi
  40094f:	callq  400820 <pthread_join@plt>
  400954:	mov    %ebx,%eax
  400956:	add    $0x1,%rbx
  40095a:	cmp    0x201730(%rip),%eax        # 602090 <nthr>
  400960:	jl     400948 <main+0xe8>
  400962:	mov    0x0(%r13),%rcx
  400966:	lea    0x674(%rip),%rdi        # 400fe1 <__dso_handle+0x159>
  40096d:	mov    $0xe,%edx
  400972:	mov    $0x1,%esi
  400977:	callq  400850 <fwrite@plt>
  40097c:	movl   $0x0,0x201706(%rip)        # 60208c <lock+0x4>
  400986:	movl   $0x0,0x2016f8(%rip)        # 602088 <lock>
  400990:	xor    %eax,%eax
  400992:	pop    %rbx
  400993:	pop    %rbp
  400994:	pop    %r12
  400996:	pop    %r13
  400998:	pop    %r14
  40099a:	retq   
  40099b:	lea    0x5ae(%rip),%rdi        # 400f50 <__dso_handle+0xc8>
  4009a2:	mov    %ebx,%esi
  4009a4:	xor    %eax,%eax
  4009a6:	callq  400ae0 <ck_error>
  4009ab:	lea    0x56e(%rip),%rdi        # 400f20 <__dso_handle+0x98>
  4009b2:	xor    %eax,%eax
  4009b4:	callq  400ae0 <ck_error>
  4009b9:	lea    0x528(%rip),%rdi        # 400ee8 <__dso_handle+0x60>
  4009c0:	xor    %eax,%eax
  4009c2:	callq  400ae0 <ck_error>
  4009c7:	lea    0x4e2(%rip),%rdi        # 400eb0 <__dso_handle+0x28>
  4009ce:	xor    %eax,%eax
  4009d0:	callq  400ae0 <ck_error>
  4009d5:	nopw   %cs:0x0(%rax,%rax,1)
  4009df:	nop

00000000004009e0 <_start>:
  4009e0:	xor    %ebp,%ebp
  4009e2:	mov    %rdx,%r9
  4009e5:	pop    %rsi
  4009e6:	mov    %rsp,%rdx
  4009e9:	and    $0xfffffffffffffff0,%rsp
  4009ed:	push   %rax
  4009ee:	push   %rsp
  4009ef:	mov    $0x400e70,%r8
  4009f6:	mov    $0x400e00,%rcx
  4009fd:	mov    $0x400860,%rdi
  400a04:	callq  *0x2015de(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  400a0a:	hlt    
  400a0b:	nopl   0x0(%rax,%rax,1)

0000000000400a10 <deregister_tm_clones>:
  400a10:	mov    $0x602087,%eax
  400a15:	push   %rbp
  400a16:	sub    $0x602080,%rax
  400a1c:	cmp    $0xe,%rax
  400a20:	mov    %rsp,%rbp
  400a23:	jbe    400a40 <deregister_tm_clones+0x30>
  400a25:	mov    $0x0,%eax
  400a2a:	test   %rax,%rax
  400a2d:	je     400a40 <deregister_tm_clones+0x30>
  400a2f:	pop    %rbp
  400a30:	mov    $0x602080,%edi
  400a35:	jmpq   *%rax
  400a37:	nopw   0x0(%rax,%rax,1)
  400a40:	pop    %rbp
  400a41:	retq   
  400a42:	nopl   0x0(%rax)
  400a46:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a50 <register_tm_clones>:
  400a50:	mov    $0x602080,%esi
  400a55:	push   %rbp
  400a56:	sub    $0x602080,%rsi
  400a5d:	sar    $0x3,%rsi
  400a61:	mov    %rsp,%rbp
  400a64:	mov    %rsi,%rax
  400a67:	shr    $0x3f,%rax
  400a6b:	add    %rax,%rsi
  400a6e:	sar    %rsi
  400a71:	je     400a88 <register_tm_clones+0x38>
  400a73:	mov    $0x0,%eax
  400a78:	test   %rax,%rax
  400a7b:	je     400a88 <register_tm_clones+0x38>
  400a7d:	pop    %rbp
  400a7e:	mov    $0x602080,%edi
  400a83:	jmpq   *%rax
  400a85:	nopl   (%rax)
  400a88:	pop    %rbp
  400a89:	retq   
  400a8a:	nopw   0x0(%rax,%rax,1)

0000000000400a90 <__do_global_dtors_aux>:
  400a90:	cmpb   $0x0,0x2015e9(%rip)        # 602080 <__TMC_END__>
  400a97:	jne    400aaa <__do_global_dtors_aux+0x1a>
  400a99:	push   %rbp
  400a9a:	mov    %rsp,%rbp
  400a9d:	callq  400a10 <deregister_tm_clones>
  400aa2:	pop    %rbp
  400aa3:	movb   $0x1,0x2015d6(%rip)        # 602080 <__TMC_END__>
  400aaa:	repz retq 
  400aac:	nopl   0x0(%rax)

0000000000400ab0 <frame_dummy>:
  400ab0:	mov    $0x601e00,%edi
  400ab5:	cmpq   $0x0,(%rdi)
  400ab9:	jne    400ac0 <frame_dummy+0x10>
  400abb:	jmp    400a50 <register_tm_clones>
  400abd:	nopl   (%rax)
  400ac0:	mov    $0x0,%eax
  400ac5:	test   %rax,%rax
  400ac8:	je     400abb <frame_dummy+0xb>
  400aca:	push   %rbp
  400acb:	mov    %rsp,%rbp
  400ace:	callq  *%rax
  400ad0:	pop    %rbp
  400ad1:	jmpq   400a50 <register_tm_clones>
  400ad6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400ae0 <ck_error>:
  400ae0:	sub    $0xd8,%rsp
  400ae7:	test   %al,%al
  400ae9:	mov    %rsi,0x28(%rsp)
  400aee:	mov    %rdx,0x30(%rsp)
  400af3:	mov    %rcx,0x38(%rsp)
  400af8:	mov    %r8,0x40(%rsp)
  400afd:	mov    %r9,0x48(%rsp)
  400b02:	je     400b3b <ck_error+0x5b>
  400b04:	movaps %xmm0,0x50(%rsp)
  400b09:	movaps %xmm1,0x60(%rsp)
  400b0e:	movaps %xmm2,0x70(%rsp)
  400b13:	movaps %xmm3,0x80(%rsp)
  400b1b:	movaps %xmm4,0x90(%rsp)
  400b23:	movaps %xmm5,0xa0(%rsp)
  400b2b:	movaps %xmm6,0xb0(%rsp)
  400b33:	movaps %xmm7,0xc0(%rsp)
  400b3b:	lea    0xe0(%rsp),%rax
  400b43:	mov    %rdi,%rsi
  400b46:	lea    0x8(%rsp),%rdx
  400b4b:	mov    %rax,0x10(%rsp)
  400b50:	lea    0x20(%rsp),%rax
  400b55:	movl   $0x8,0x8(%rsp)
  400b5d:	movl   $0x30,0xc(%rsp)
  400b65:	mov    %rax,0x18(%rsp)
  400b6a:	mov    0x201487(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400b71:	mov    (%rax),%rdi
  400b74:	callq  400830 <vfprintf@plt>
  400b79:	mov    $0x1,%edi
  400b7e:	callq  400840 <exit@plt>
  400b83:	nopl   (%rax)
  400b86:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b90 <thread>:
  400b90:	push   %rbx
  400b91:	add    $0xffffffffffffff80,%rsp
  400b95:	mov    0x2014fd(%rip),%esi        # 602098 <a>
  400b9b:	lock xadd %esi,0x2014f9(%rip)        # 60209c <a+0x4>
  400ba3:	xor    %eax,%eax
  400ba5:	mov    $0x10,%ecx
  400baa:	mov    %rsp,%rdi
  400bad:	rep stos %rax,%es:(%rdi)
  400bb0:	mov    %esi,%ecx
  400bb2:	mov    $0x1,%eax
  400bb7:	mov    $0xba,%edi
  400bbc:	and    $0x3,%ecx
  400bbf:	shl    %cl,%rax
  400bc2:	mov    %rax,(%rsp)
  400bc6:	xor    %eax,%eax
  400bc8:	callq  4007e0 <syscall@plt>
  400bcd:	mov    %rsp,%rdx
  400bd0:	mov    $0x80,%esi
  400bd5:	mov    %eax,%edi
  400bd7:	callq  4007b0 <sched_setaffinity@plt>
  400bdc:	test   %eax,%eax
  400bde:	jne    400d9e <thread+0x20e>
  400be4:	lea    0x20149d(%rip),%rsi        # 602088 <lock>
  400beb:	mov    $0xf4240,%ecx
  400bf0:	mov    (%rsi),%eax
  400bf2:	jmp    400bfd <thread+0x6d>
  400bf4:	nopl   0x0(%rax)
  400bf8:	pause  
  400bfa:	mov    (%rsp),%eax
  400bfd:	mov    %eax,%edx
  400bff:	and    $0x7f,%dh
  400c02:	add    $0x1,%edx
  400c05:	lock cmpxchg %edx,0x20147b(%rip)        # 602088 <lock>
  400c0d:	mov    %eax,(%rsp)
  400c10:	sete   %al
  400c13:	test   %al,%al
  400c15:	je     400bf8 <thread+0x68>
  400c17:	mov    (%rsp),%edx
  400c1a:	mov    0x20146c(%rip),%eax        # 60208c <lock+0x4>
  400c20:	cmp    %eax,%edx
  400c22:	je     400c34 <thread+0xa4>
  400c24:	nopl   0x0(%rax)
  400c28:	pause  
  400c2a:	mov    0x20145c(%rip),%eax        # 60208c <lock+0x4>
  400c30:	cmp    %eax,%edx
  400c32:	jne    400c28 <thread+0x98>
  400c34:	mov    0x20145a(%rip),%edx        # 602094 <locked>
  400c3a:	test   %edx,%edx
  400c3c:	jne    400db4 <thread+0x224>
  400c42:	lock incl 0x20144b(%rip)        # 602094 <locked>
  400c49:	lock incl 0x201444(%rip)        # 602094 <locked>
  400c50:	lock incl 0x20143d(%rip)        # 602094 <locked>
  400c57:	lock incl 0x201436(%rip)        # 602094 <locked>
  400c5e:	lock incl 0x20142f(%rip)        # 602094 <locked>
  400c65:	lock incl 0x201428(%rip)        # 602094 <locked>
  400c6c:	lock incl 0x201421(%rip)        # 602094 <locked>
  400c73:	lock incl 0x20141a(%rip)        # 602094 <locked>
  400c7a:	mov    0x201414(%rip),%edx        # 602094 <locked>
  400c80:	cmp    $0x8,%edx
  400c83:	jne    400dc7 <thread+0x237>
  400c89:	lock decl 0x201404(%rip)        # 602094 <locked>
  400c90:	lock decl 0x2013fd(%rip)        # 602094 <locked>
  400c97:	lock decl 0x2013f6(%rip)        # 602094 <locked>
  400c9e:	lock decl 0x2013ef(%rip)        # 602094 <locked>
  400ca5:	lock decl 0x2013e8(%rip)        # 602094 <locked>
  400cac:	lock decl 0x2013e1(%rip)        # 602094 <locked>
  400cb3:	lock decl 0x2013da(%rip)        # 602094 <locked>
  400cba:	lock decl 0x2013d3(%rip)        # 602094 <locked>
  400cc1:	mov    0x2013cd(%rip),%edx        # 602094 <locked>
  400cc7:	test   %edx,%edx
  400cc9:	jne    400dda <thread+0x24a>
  400ccf:	mov    0x2013b7(%rip),%eax        # 60208c <lock+0x4>
  400cd5:	jmp    400ce5 <thread+0x155>
  400cd7:	nopw   0x0(%rax,%rax,1)
  400ce0:	pause  
  400ce2:	mov    (%rsp),%eax
  400ce5:	mov    %eax,%edx
  400ce7:	and    $0x7f,%dh
  400cea:	add    $0x1,%edx
  400ced:	lock cmpxchg %edx,0x201397(%rip)        # 60208c <lock+0x4>
  400cf5:	mov    %eax,(%rsp)
  400cf8:	sete   %al
  400cfb:	test   %al,%al
  400cfd:	je     400ce0 <thread+0x150>
  400cff:	mov    (%rsi),%eax
  400d01:	jmp    400d0d <thread+0x17d>
  400d03:	nopl   0x0(%rax,%rax,1)
  400d08:	pause  
  400d0a:	mov    (%rsp),%eax
  400d0d:	mov    %eax,%edx
  400d0f:	and    $0x7fffffff,%edx
  400d15:	add    $0x10000,%edx
  400d1b:	lock cmpxchg %edx,0x201365(%rip)        # 602088 <lock>
  400d23:	mov    %eax,(%rsp)
  400d26:	sete   %al
  400d29:	test   %al,%al
  400d2b:	je     400d08 <thread+0x178>
  400d2d:	movzwl (%rsp),%edx
  400d31:	mov    0x201355(%rip),%eax        # 60208c <lock+0x4>
  400d37:	movzwl %ax,%eax
  400d3a:	cmp    %edx,%eax
  400d3c:	je     400d4f <thread+0x1bf>
  400d3e:	xchg   %ax,%ax
  400d40:	pause  
  400d42:	mov    0x201344(%rip),%eax        # 60208c <lock+0x4>
  400d48:	movzwl %ax,%eax
  400d4b:	cmp    %eax,%edx
  400d4d:	jne    400d40 <thread+0x1b0>
  400d4f:	mov    0x20133f(%rip),%edx        # 602094 <locked>
  400d55:	test   %edx,%edx
  400d57:	jne    400ded <thread+0x25d>
  400d5d:	mov    0x201329(%rip),%eax        # 60208c <lock+0x4>
  400d63:	jmp    400d6d <thread+0x1dd>
  400d65:	nopl   (%rax)
  400d68:	pause  
  400d6a:	mov    (%rsp),%eax
  400d6d:	mov    %eax,%edx
  400d6f:	and    $0x7fffffff,%edx
  400d75:	add    $0x10000,%edx
  400d7b:	lock cmpxchg %edx,0x201309(%rip)        # 60208c <lock+0x4>
  400d83:	mov    %eax,(%rsp)
  400d86:	sete   %al
  400d89:	test   %al,%al
  400d8b:	je     400d68 <thread+0x1d8>
  400d8d:	sub    $0x1,%ecx
  400d90:	jne    400bf0 <thread+0x60>
  400d96:	sub    $0xffffffffffffff80,%rsp
  400d9a:	xor    %eax,%eax
  400d9c:	pop    %rbx
  400d9d:	retq   
  400d9e:	lea    0xeb(%rip),%rdi        # 400e90 <__dso_handle+0x8>
  400da5:	callq  400810 <perror@plt>
  400daa:	mov    $0x1,%edi
  400daf:	callq  400840 <exit@plt>
  400db4:	lea    0x1bd(%rip),%rdi        # 400f78 <__dso_handle+0xf0>
  400dbb:	mov    $0x44,%esi
  400dc0:	xor    %eax,%eax
  400dc2:	callq  400ae0 <ck_error>
  400dc7:	lea    0x1c2(%rip),%rdi        # 400f90 <__dso_handle+0x108>
  400dce:	mov    $0x52,%esi
  400dd3:	xor    %eax,%eax
  400dd5:	callq  400ae0 <ck_error>
  400dda:	lea    0x197(%rip),%rdi        # 400f78 <__dso_handle+0xf0>
  400de1:	mov    $0x60,%esi
  400de6:	xor    %eax,%eax
  400de8:	callq  400ae0 <ck_error>
  400ded:	lea    0x1b4(%rip),%rdi        # 400fa8 <__dso_handle+0x120>
  400df4:	mov    $0x69,%esi
  400df9:	xor    %eax,%eax
  400dfb:	callq  400ae0 <ck_error>

0000000000400e00 <__libc_csu_init>:
  400e00:	push   %r15
  400e02:	push   %r14
  400e04:	mov    %edi,%r15d
  400e07:	push   %r13
  400e09:	push   %r12
  400e0b:	lea    0x200fde(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400e12:	push   %rbp
  400e13:	lea    0x200fde(%rip),%rbp        # 601df8 <__init_array_end>
  400e1a:	push   %rbx
  400e1b:	mov    %rsi,%r14
  400e1e:	mov    %rdx,%r13
  400e21:	sub    %r12,%rbp
  400e24:	sub    $0x8,%rsp
  400e28:	sar    $0x3,%rbp
  400e2c:	callq  400770 <_init>
  400e31:	test   %rbp,%rbp
  400e34:	je     400e56 <__libc_csu_init+0x56>
  400e36:	xor    %ebx,%ebx
  400e38:	nopl   0x0(%rax,%rax,1)
  400e40:	mov    %r13,%rdx
  400e43:	mov    %r14,%rsi
  400e46:	mov    %r15d,%edi
  400e49:	callq  *(%r12,%rbx,8)
  400e4d:	add    $0x1,%rbx
  400e51:	cmp    %rbx,%rbp
  400e54:	jne    400e40 <__libc_csu_init+0x40>
  400e56:	add    $0x8,%rsp
  400e5a:	pop    %rbx
  400e5b:	pop    %rbp
  400e5c:	pop    %r12
  400e5e:	pop    %r13
  400e60:	pop    %r14
  400e62:	pop    %r15
  400e64:	retq   
  400e65:	nop
  400e66:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400e70 <__libc_csu_fini>:
  400e70:	repz retq 

Disassembly of section .fini:

0000000000400e74 <_fini>:
  400e74:	sub    $0x8,%rsp
  400e78:	add    $0x8,%rsp
  400e7c:	retq   
