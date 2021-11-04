// TC_OUT _Z11create_condP14PFS_cond_classPKv,0xef279b,0xef27a7,0x0(0x1e8c1f8)
// TC_OUT _Z11create_condP14PFS_cond_classPKv,0xef27da,0xef27e3,0x0(%r13)
// TC_OUT _Z11create_condP14PFS_cond_classPKv,0xef2824,0xef282a,0x0(%rdx)
// TC_OUT _Z11create_condP14PFS_cond_classPKv,0xef28bf,0xef28c8,0x0(%r13)
// TC_OUT _Z11create_condP14PFS_cond_classPKv,0xef2a41,0xef2a4d,0x0(0x1e8c1b8)
// TC_OUT _Z11create_condP14PFS_cond_classPKv,0xef2a7d,0xef2a89,0x1e8c1a8(%rdx)
// TC_OUT _Z11create_condP14PFS_cond_classPKv,0xef2ac4,0xef2aca,0x0(%rdx)
0000000000ef2770 <_Z11create_condP14PFS_cond_classPKv>:
  ef2770:	push   %rbp
  ef2771:	mov    %rsp,%rbp
  ef2774:	push   %r15
  ef2776:	push   %r14
  ef2778:	push   %r13
  ef277a:	push   %r12
  ef277c:	push   %rbx
  ef277d:	sub    $0x18,%rsp
  ef2781:	cmpb   $0x0,0xf99a21(%rip)        # 1e8c1a9 <global_cond_container+0x9>
  ef2788:	mov    %rsi,-0x38(%rbp)
  ef278c:	jne    ef2b26 <_Z11create_condP14PFS_cond_classPKv+0x3b6>
  ef2792:	mov    0xf99a60(%rip),%eax        # 1e8c1f8 <global_cond_container+0x58>
  ef2798:	mov    %rdi,%rbx
  ef279b:	mov    %eax,%r15d
  ef279e:	lock cmpxchg %r15d,0xf99a51(%rip)        # 1e8c1f8 <global_cond_container+0x58>
  ef27a7:	jne    ef279b <_Z11create_condP14PFS_cond_classPKv+0x2b>
  ef27a9:	xor    %edx,%edx
  ef27ab:	test   %r15d,%r15d
  ef27ae:	jne    ef2a3b <_Z11create_condP14PFS_cond_classPKv+0x2cb>
  ef27b4:	cmp    %rdx,0xf99a7d(%rip)        # 1e8c238 <global_cond_container+0x98>
  ef27bb:	mov    %r15d,%eax
  ef27be:	jbe    ef287b <_Z11create_condP14PFS_cond_classPKv+0x10b>
  ef27c4:	nopl   0x0(%rax)
  ef27c8:	lea    0x1e8c240(,%rax,8),%r12
  ef27d0:	mov    0x8(%r12),%rax
  ef27d5:	lea    0x8(%r12),%r13
  ef27da:	mov    %rax,%r14
  ef27dd:	lock cmpxchg %rax,0x0(%r13)
  ef27e3:	jne    ef27da <_Z11create_condP14PFS_cond_classPKv+0x6a>
  ef27e5:	test   %r14,%r14
  ef27e8:	je     ef28b0 <_Z11create_condP14PFS_cond_classPKv+0x140>
  ef27ee:	cmpb   $0x0,(%r14)
  ef27f2:	jne    ef2867 <_Z11create_condP14PFS_cond_classPKv+0xf7>
  ef27f4:	lea    0x4(%r14),%rsi
  ef27f8:	mov    $0x1,%eax
  ef27fd:	lock xadd %eax,(%rsi)
  ef2801:	mov    0x50(%r14),%rcx
  ef2805:	lea    (%rax,%rcx,1),%edi
  ef2808:	cmp    %edi,%eax
  ef280a:	jae    ef28a0 <_Z11create_condP14PFS_cond_classPKv+0x130>
  ef2810:	mov    %eax,%eax
  ef2812:	xor    %edx,%edx
  ef2814:	div    %rcx
  ef2817:	shl    $0x6,%rdx
  ef281b:	add    0x48(%r14),%rdx
  ef281f:	mov    (%rdx),%eax
  ef2821:	mov    %rdx,%r8
  ef2824:	mov    %eax,%ecx
  ef2826:	lock cmpxchg %eax,(%rdx)
  ef282a:	jne    ef2824 <_Z11create_condP14PFS_cond_classPKv+0xb4>
  ef282c:	test   $0x3,%cl
  ef282f:	je     ef2848 <_Z11create_condP14PFS_cond_classPKv+0xd8>
  ef2831:	mov    $0x1,%eax
  ef2836:	lock xadd %eax,(%rsi)
  ef283a:	cmp    %eax,%edi
  ef283c:	jbe    ef28a0 <_Z11create_condP14PFS_cond_classPKv+0x130>
  ef283e:	mov    0x50(%r14),%rcx
  ef2842:	jmp    ef2810 <_Z11create_condP14PFS_cond_classPKv+0xa0>
  ef2844:	nopl   0x0(%rax)
  ef2848:	mov    %ecx,%r9d
  ef284b:	mov    %ecx,%eax
  ef284d:	and    $0xfffffffc,%r9d
  ef2851:	add    $0x1,%r9d
  ef2855:	lock cmpxchg %r9d,(%rdx)
  ef285a:	cmp    %eax,%ecx
  ef285c:	jne    ef2831 <_Z11create_condP14PFS_cond_classPKv+0xc1>
  ef285e:	test   %rdx,%rdx
  ef2861:	jne    ef28e8 <_Z11create_condP14PFS_cond_classPKv+0x178>
  ef2867:	add    $0x1,%r15d
  ef286b:	mov    %r15d,%eax
  ef286e:	cmp    0xf999c3(%rip),%rax        # 1e8c238 <global_cond_container+0x98>
  ef2875:	jb     ef27c8 <_Z11create_condP14PFS_cond_classPKv+0x58>
  ef287b:	addq   $0x1,0xf9991d(%rip)        # 1e8c1a0 <global_cond_container>
  ef2883:	movb   $0x1,0xf9991f(%rip)        # 1e8c1a9 <global_cond_container+0x9>
  ef288a:	xor    %eax,%eax
  ef288c:	add    $0x18,%rsp
  ef2890:	pop    %rbx
  ef2891:	pop    %r12
  ef2893:	pop    %r13
  ef2895:	pop    %r14
  ef2897:	pop    %r15
  ef2899:	pop    %rbp
  ef289a:	retq   
  ef289b:	nopl   0x0(%rax,%rax,1)
  ef28a0:	movb   $0x1,(%r14)
  ef28a4:	jmp    ef2867 <_Z11create_condP14PFS_cond_classPKv+0xf7>
  ef28a6:	nopw   %cs:0x0(%rax,%rax,1)
  ef28b0:	mov    $0x1e8ca50,%edi
  ef28b5:	callq  7620e0 <pthread_mutex_lock@plt>
  ef28ba:	mov    0x8(%r12),%rax
  ef28bf:	mov    %rax,%rdx
  ef28c2:	lock cmpxchg %rax,0x0(%r13)
  ef28c8:	jne    ef28bf <_Z11create_condP14PFS_cond_classPKv+0x14f>
  ef28ca:	test   %rdx,%rdx
  ef28cd:	mov    %rdx,%r14
  ef28d0:	je     ef2961 <_Z11create_condP14PFS_cond_classPKv+0x1f1>
  ef28d6:	mov    $0x1e8ca50,%edi
  ef28db:	callq  762030 <pthread_mutex_unlock@plt>
  ef28e0:	jmpq   ef27ee <_Z11create_condP14PFS_cond_classPKv+0x7e>
  ef28e5:	nopl   (%rax)
  ef28e8:	mov    %r14,0x8(%rdx)
  ef28ec:	mov    %rdx,%rax
  ef28ef:	mov    -0x38(%rbp),%rsi
  ef28f3:	mov    %rbx,0x18(%rax)
  ef28f7:	xor    %edx,%edx
  ef28f9:	movzbl 0xfa2340(%rip),%ecx        # 1e94c40 <flag_global_instrumentation>
  ef2900:	mov    %rsi,0x10(%rax)
  ef2904:	cmpb   $0x0,0x4(%rbx)
  ef2908:	cmovne %ecx,%edx
  ef290b:	mov    %dl,0x4(%rax)
  ef290e:	movzbl 0x5(%rbx),%edx
  ef2912:	movq   $0x0,0x20(%rax)
  ef291a:	movq   $0x0,0x28(%rax)
  ef2922:	movq   $0xffffffffffffffff,0x30(%rax)
  ef292a:	movq   $0x0,0x38(%rax)
  ef2932:	mov    %dl,0x5(%rax)
  ef2935:	mov    %r9d,%edx
  ef2938:	and    $0xfffffffc,%edx
  ef293b:	add    $0x6,%edx
  ef293e:	xchg   %edx,(%r8)
  ef2941:	testb  $0x1,0x8(%rbx)
  ef2945:	je     ef288c <_Z11create_condP14PFS_cond_classPKv+0x11c>
  ef294b:	mov    %rax,0xc0(%rbx)
  ef2952:	add    $0x18,%rsp
  ef2956:	pop    %rbx
  ef2957:	pop    %r12
  ef2959:	pop    %r13
  ef295b:	pop    %r14
  ef295d:	pop    %r15
  ef295f:	pop    %rbp
  ef2960:	retq   
  ef2961:	mov    $0x60,%edi
  ef2966:	mov    %rdx,-0x40(%rbp)
  ef296a:	callq  761ea0 <_Znwm@plt>
  ef296f:	mov    -0x40(%rbp),%rdx
  ef2973:	mov    %rax,%rdi
  ef2976:	mov    %rax,%r14
  ef2979:	mov    $0xc,%ecx
  ef297e:	mov    %rdx,%rax
  ef2981:	rep stos %rax,%es:(%rdi)
  ef2984:	movb   $0x1,0xf9c2b5(%rip)        # 1e8ec40 <builtin_memory_scalable_buffer+0xc0>
  ef298b:	mov    0xf9c2d6(%rip),%rax        # 1e8ec68 <builtin_memory_scalable_buffer+0xe8>
  ef2992:	addq   $0x1,0xf9c2ae(%rip)        # 1e8ec48 <builtin_memory_scalable_buffer+0xc8>
  ef299a:	addq   $0x1,0xf9c2ce(%rip)        # 1e8ec70 <builtin_memory_scalable_buffer+0xf0>
  ef29a2:	addq   $0x60,0xf9c2ae(%rip)        # 1e8ec58 <builtin_memory_scalable_buffer+0xd8>
  ef29aa:	addq   $0x60,0xf9c2ce(%rip)        # 1e8ec80 <builtin_memory_scalable_buffer+0x100>
  ef29b2:	test   %rax,%rax
  ef29b5:	je     ef29c2 <_Z11create_condP14PFS_cond_classPKv+0x252>
  ef29b7:	sub    $0x1,%rax
  ef29bb:	mov    %rax,0xf9c2a6(%rip)        # 1e8ec68 <builtin_memory_scalable_buffer+0xe8>
  ef29c2:	mov    0xf9c2af(%rip),%rax        # 1e8ec78 <builtin_memory_scalable_buffer+0xf8>
  ef29c9:	cmp    $0x5f,%rax
  ef29cd:	jbe    ef29da <_Z11create_condP14PFS_cond_classPKv+0x26a>
  ef29cf:	sub    $0x60,%rax
  ef29d3:	mov    %rax,0xf9c29e(%rip)        # 1e8ec78 <builtin_memory_scalable_buffer+0xf8>
  ef29da:	lea    0x1(%r15),%eax
  ef29de:	cmp    %rax,0xf99853(%rip)        # 1e8c238 <global_cond_container+0x98>
  ef29e5:	jbe    ef2b33 <_Z11create_condP14PFS_cond_classPKv+0x3c3>
  ef29eb:	movq   $0x100,0x50(%r14)
  ef29f3:	mov    $0x100,%esi
  ef29f8:	mov    0xf9a049(%rip),%rax        # 1e8ca48 <global_cond_container+0x8a8>
  ef29ff:	movq   $0x0,0x48(%r14)
  ef2a07:	movb   $0x1,(%r14)
  ef2a0b:	movl   $0x0,0x4(%r14)
  ef2a13:	mov    (%rax),%rdi
  ef2a16:	mov    $0x20,%ecx
  ef2a1b:	mov    $0x40,%edx
  ef2a20:	callq  eeedd0 <_Z16pfs_malloc_arrayP24PFS_builtin_memory_classmmi>
  ef2a25:	test   %rax,%rax
  ef2a28:	mov    %rax,0x48(%r14)
  ef2a2c:	je     ef2b89 <_Z11create_condP14PFS_cond_classPKv+0x419>
  ef2a32:	movb   $0x0,(%r14)
  ef2a36:	jmpq   ef2b61 <_Z11create_condP14PFS_cond_classPKv+0x3f1>
  ef2a3b:	mov    0xf99777(%rip),%eax        # 1e8c1b8 <global_cond_container+0x18>
  ef2a41:	mov    %eax,%ecx
  ef2a43:	mov    %eax,%edx
  ef2a45:	lock cmpxchg %eax,0xf9976b(%rip)        # 1e8c1b8 <global_cond_container+0x18>
  ef2a4d:	jne    ef2a41 <_Z11create_condP14PFS_cond_classPKv+0x2d1>
  ef2a4f:	lea    (%rcx,%r15,1),%r11d
  ef2a53:	cmp    %r11d,%ecx
  ef2a56:	jae    ef2b19 <_Z11create_condP14PFS_cond_classPKv+0x3a9>
  ef2a5c:	nopl   0x0(%rax)
  ef2a60:	mov    %edx,%eax
  ef2a62:	xor    %edx,%edx
  ef2a64:	div    %r15d
  ef2a67:	mov    %edx,%edx
  ef2a69:	lea    0x14(%rdx),%rax
  ef2a6d:	lea    0x0(,%rax,8),%rdx
  ef2a75:	mov    0x1e8c1a8(,%rax,8),%rax
  ef2a7d:	mov    %rax,%rdi
  ef2a80:	lock cmpxchg %rdi,0x1e8c1a8(%rdx)
  ef2a89:	jne    ef2a7d <_Z11create_condP14PFS_cond_classPKv+0x30d>
  ef2a8b:	test   %rdi,%rdi
  ef2a8e:	je     ef2b03 <_Z11create_condP14PFS_cond_classPKv+0x393>
  ef2a90:	cmpb   $0x0,(%rdi)
  ef2a93:	jne    ef2b03 <_Z11create_condP14PFS_cond_classPKv+0x393>
  ef2a95:	lea    0x4(%rdi),%rsi
  ef2a99:	mov    $0x1,%eax
  ef2a9e:	lock xadd %eax,(%rsi)
  ef2aa2:	mov    0x50(%rdi),%rcx
  ef2aa6:	lea    (%rax,%rcx,1),%r10d
  ef2aaa:	cmp    %r10d,%eax
  ef2aad:	jae    ef2b21 <_Z11create_condP14PFS_cond_classPKv+0x3b1>
  ef2aaf:	nop
  ef2ab0:	mov    %eax,%eax
  ef2ab2:	xor    %edx,%edx
  ef2ab4:	div    %rcx
  ef2ab7:	shl    $0x6,%rdx
  ef2abb:	add    0x48(%rdi),%rdx
  ef2abf:	mov    (%rdx),%eax
  ef2ac1:	mov    %rdx,%r8
  ef2ac4:	mov    %eax,%ecx
  ef2ac6:	lock cmpxchg %eax,(%rdx)
  ef2aca:	jne    ef2ac4 <_Z11create_condP14PFS_cond_classPKv+0x354>
  ef2acc:	test   $0x3,%cl
  ef2acf:	je     ef2ae8 <_Z11create_condP14PFS_cond_classPKv+0x378>
  ef2ad1:	mov    $0x1,%eax
  ef2ad6:	lock xadd %eax,(%rsi)
  ef2ada:	cmp    %eax,%r10d
  ef2add:	jbe    ef2b21 <_Z11create_condP14PFS_cond_classPKv+0x3b1>
  ef2adf:	mov    0x50(%rdi),%rcx
  ef2ae3:	jmp    ef2ab0 <_Z11create_condP14PFS_cond_classPKv+0x340>
  ef2ae5:	nopl   (%rax)
  ef2ae8:	mov    %ecx,%r9d
  ef2aeb:	mov    %ecx,%eax
  ef2aed:	and    $0xfffffffc,%r9d
  ef2af1:	add    $0x1,%r9d
  ef2af5:	lock cmpxchg %r9d,(%rdx)
  ef2afa:	cmp    %eax,%ecx
  ef2afc:	jne    ef2ad1 <_Z11create_condP14PFS_cond_classPKv+0x361>
  ef2afe:	test   %rdx,%rdx
  ef2b01:	jne    ef2b7d <_Z11create_condP14PFS_cond_classPKv+0x40d>
  ef2b03:	mov    $0x1,%edx
  ef2b08:	lock xadd %edx,0xf996a8(%rip)        # 1e8c1b8 <global_cond_container+0x18>
  ef2b10:	cmp    %edx,%r11d
  ef2b13:	ja     ef2a60 <_Z11create_condP14PFS_cond_classPKv+0x2f0>
  ef2b19:	mov    %r15d,%edx
  ef2b1c:	jmpq   ef27b4 <_Z11create_condP14PFS_cond_classPKv+0x44>
  ef2b21:	movb   $0x1,(%rdi)
  ef2b24:	jmp    ef2b03 <_Z11create_condP14PFS_cond_classPKv+0x393>
  ef2b26:	addq   $0x1,0xf99672(%rip)        # 1e8c1a0 <global_cond_container>
  ef2b2e:	jmpq   ef288a <_Z11create_condP14PFS_cond_classPKv+0x11a>
  ef2b33:	mov    0xf99707(%rip),%esi        # 1e8c240 <global_cond_container+0xa0>
  ef2b39:	test   %rsi,%rsi
  ef2b3c:	mov    %rsi,0x50(%r14)
  ef2b40:	mov    0xf99f01(%rip),%rax        # 1e8ca48 <global_cond_container+0x8a8>
  ef2b47:	movq   $0x0,0x48(%r14)
  ef2b4f:	movb   $0x1,(%r14)
  ef2b53:	movl   $0x0,0x4(%r14)
  ef2b5b:	jne    ef2a13 <_Z11create_condP14PFS_cond_classPKv+0x2a3>
  ef2b61:	mov    %r14,%rax
  ef2b64:	movq   $0x1e8c1a0,0x58(%r14)
  ef2b6c:	xchg   %rax,0x0(%r13)
  ef2b70:	lock addl $0x1,0xf99680(%rip)        # 1e8c1f8 <global_cond_container+0x58>
  ef2b78:	jmpq   ef28d6 <_Z11create_condP14PFS_cond_classPKv+0x166>
  ef2b7d:	mov    %rdi,0x8(%rdx)
  ef2b81:	mov    %rdx,%rax
  ef2b84:	jmpq   ef28ef <_Z11create_condP14PFS_cond_classPKv+0x17f>
  ef2b89:	mov    0xf99eb8(%rip),%rax        # 1e8ca48 <global_cond_container+0x8a8>
  ef2b90:	mov    0x50(%r14),%rsi
  ef2b94:	xor    %ecx,%ecx
  ef2b96:	mov    $0x40,%edx
  ef2b9b:	mov    (%rax),%rdi
  ef2b9e:	callq  eeeeb0 <_Z14pfs_free_arrayP24PFS_builtin_memory_classmmPv>
  ef2ba3:	movq   $0x0,0x48(%r14)
  ef2bab:	mov    %r14,%rdi
  ef2bae:	callq  7625e0 <_ZdlPv@plt>
  ef2bb3:	mov    0xf9c0b6(%rip),%rax        # 1e8ec70 <builtin_memory_scalable_buffer+0xf0>
  ef2bba:	addq   $0x1,0xf9c08e(%rip)        # 1e8ec50 <builtin_memory_scalable_buffer+0xd0>
  ef2bc2:	addq   $0x1,0xf9c09e(%rip)        # 1e8ec68 <builtin_memory_scalable_buffer+0xe8>
  ef2bca:	movb   $0x1,0xf9c06f(%rip)        # 1e8ec40 <builtin_memory_scalable_buffer+0xc0>
  ef2bd1:	addq   $0x60,0xf9c087(%rip)        # 1e8ec60 <builtin_memory_scalable_buffer+0xe0>
  ef2bd9:	addq   $0x60,0xf9c097(%rip)        # 1e8ec78 <builtin_memory_scalable_buffer+0xf8>
  ef2be1:	test   %rax,%rax
  ef2be4:	je     ef2bf1 <_Z11create_condP14PFS_cond_classPKv+0x481>
  ef2be6:	sub    $0x1,%rax
  ef2bea:	mov    %rax,0xf9c07f(%rip)        # 1e8ec70 <builtin_memory_scalable_buffer+0xf0>
  ef2bf1:	mov    0xf9c088(%rip),%rax        # 1e8ec80 <builtin_memory_scalable_buffer+0x100>
  ef2bf8:	cmp    $0x5f,%rax
  ef2bfc:	jbe    ef2c09 <_Z11create_condP14PFS_cond_classPKv+0x499>
  ef2bfe:	sub    $0x60,%rax
  ef2c02:	mov    %rax,0xf9c077(%rip)        # 1e8ec80 <builtin_memory_scalable_buffer+0x100>
  ef2c09:	mov    $0x1e8ca50,%edi
  ef2c0e:	addq   $0x1,0xf9958a(%rip)        # 1e8c1a0 <global_cond_container>
  ef2c16:	callq  762030 <pthread_mutex_unlock@plt>
  ef2c1b:	jmpq   ef288a <_Z11create_condP14PFS_cond_classPKv+0x11a>
