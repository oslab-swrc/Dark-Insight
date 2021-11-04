// TC_OUT _Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm,0x1092061,0x1092076,0x0(%rbx)
// TC_OUT _Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm,0x109217e,0x1092193,0x0(%rbx)
0000000001092010 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm>:
 1092010:	push   %rbp
 1092011:	mov    %rsp,%rbp
 1092014:	push   %r15
 1092016:	mov    %rdx,%r15
 1092019:	push   %r14
 109201b:	mov    %rcx,%r14
 109201e:	push   %r13
 1092020:	push   %r12
 1092022:	xor    %r12d,%r12d
 1092025:	push   %rbx
 1092026:	mov    %rdi,%rbx
 1092029:	sub    $0x28,%rsp
 109202d:	movq   $0x0,-0x48(%rbp)
 1092035:	movq   $0x0,-0x50(%rbp)
 109203d:	mov    0xd1205c(%rip),%rax        # 1da40a0 <srv_n_spin_wait_rounds>
 1092044:	cmp    %rax,%r12
 1092047:	jae    109215b <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x14b>
 109204d:	nopl   (%rax)
 1092050:	mov    (%rbx),%rdx
 1092053:	test   %rdx,%rdx
 1092056:	jle    10920d8 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0xc8>
 109205c:	addq   $0x1,-0x50(%rbp)
 1092061:	mov    (%rbx),%rax
 1092064:	test   %rax,%rax
 1092067:	jle    10921fa <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x1ea>
 109206d:	lea    -0x1(%rax),%rdx
 1092071:	lock cmpxchg %rdx,(%rbx)
 1092076:	jne    1092061 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x51>
 1092078:	mov    0x58(%rbx),%eax
 109207b:	and    $0x3fff,%r14d
 1092082:	mov    %r15,0x48(%rbx)
 1092086:	shl    $0xe,%r14d
 109208a:	and    $0xf0003fff,%eax
 109208f:	or     %r14d,%eax
 1092092:	mov    %eax,0x58(%rbx)
 1092095:	cmpq   $0x0,-0x48(%rbp)
 109209a:	jne    10921c9 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x1b9>
 10920a0:	callq  12e0670 <my_timer_cycles>
 10920a5:	test   %rax,%rax
 10920a8:	jne    10920af <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x9f>
 10920aa:	callq  fda000 <_Z21os_thread_get_curr_idv>
 10920af:	and    $0x3f,%eax
 10920b2:	mov    -0x50(%rbp),%rsi
 10920b6:	lea    0x8(,%rax,8),%rax
 10920be:	add    %rsi,0x1ec6330(,%rax,8)
 10920c6:	add    $0x28,%rsp
 10920ca:	pop    %rbx
 10920cb:	pop    %r12
 10920cd:	pop    %r13
 10920cf:	pop    %r14
 10920d1:	pop    %r15
 10920d3:	pop    %rbp
 10920d4:	retq   
 10920d5:	nopl   (%rax)
 10920d8:	mov    0xd11fb1(%rip),%rcx        # 1da4090 <srv_spin_wait_delay>
 10920df:	test   %rcx,%rcx
 10920e2:	je     109214e <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x13e>
 10920e4:	mov    0xd122dd(%rip),%rax        # 1da43c8 <ut_rnd_ulint_counter>
 10920eb:	xor    %edx,%edx
 10920ed:	imul   $0x901dfa9,%rax,%rax
 10920f4:	add    $0x723c79d,%rax
 10920fa:	mov    %rax,0xd122c7(%rip)        # 1da43c8 <ut_rnd_ulint_counter>
 1092101:	imul   $0x723c79d,%rax,%rax
 1092108:	add    $0x78eb309,%rax
 109210e:	xor    $0xb2fc09e,%rax
 1092114:	rol    $0x14,%rax
 1092118:	imul   $0x51b8497,%rax,%rax
 109211f:	add    $0x3c8e906,%rax
 1092125:	xor    $0x88e3703,%rax
 109212b:	rol    $0x14,%rax
 109212f:	imul   $0x901dfa9,%rax,%rax
 1092136:	add    $0x5e34832,%rax
 109213c:	div    %rcx
 109213f:	mov    %rdx,%rdi
 1092142:	callq  10de670 <_Z8ut_delaym>
 1092147:	mov    0xd11f52(%rip),%rax        # 1da40a0 <srv_n_spin_wait_rounds>
 109214e:	add    $0x1,%r12
 1092152:	cmp    %rax,%r12
 1092155:	jb     1092050 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x40>
 109215b:	callq  fda350 <_Z15os_thread_yieldv>
 1092160:	jmpq   109205c <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x4c>
 1092165:	nopl   (%rax)
 1092168:	test   %rax,%rax
 109216b:	je     1092295 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x285>
 1092171:	mov    $0x1,%edx
 1092176:	xor    %eax,%eax
 1092178:	lock cmpxchg %rdx,0x8(%rbx)
 109217e:	mov    (%rbx),%rax
 1092181:	test   %rax,%rax
 1092184:	jle    109229a <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x28a>
 109218a:	lea    -0x1(%rax),%rdx
 109218e:	lock cmpxchg %rdx,(%rbx)
 1092193:	jne    109217e <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x16e>
 1092195:	mov    0x58(%rbx),%eax
 1092198:	and    $0x3fff,%r14d
 109219f:	lea    -0x40(%rbp),%rsi
 10921a3:	shl    $0xe,%r14d
 10921a7:	mov    %r15,0x48(%rbx)
 10921ab:	mov    %r13,%rdi
 10921ae:	and    $0xf0003fff,%eax
 10921b3:	or     %r14d,%eax
 10921b6:	mov    %eax,0x58(%rbx)
 10921b9:	callq  10903a0 <_Z20sync_array_free_cellP12sync_array_tRP11sync_cell_t>
 10921be:	cmpq   $0x0,-0x48(%rbp)
 10921c3:	je     10920a0 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x90>
 10921c9:	mov    -0x48(%rbp),%eax
 10921cc:	add    %eax,0x60(%rbx)
 10921cf:	callq  12e0670 <my_timer_cycles>
 10921d4:	test   %rax,%rax
 10921d7:	jne    10921de <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x1ce>
 10921d9:	callq  fda000 <_Z21os_thread_get_curr_idv>
 10921de:	and    $0x3f,%eax
 10921e1:	mov    -0x48(%rbp),%rsi
 10921e5:	lea    0x8(,%rax,8),%rax
 10921ed:	add    %rsi,0x1ec7378(,%rax,8)
 10921f5:	jmpq   10920a0 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x90>
 10921fa:	cmp    0xd11e9f(%rip),%r12        # 1da40a0 <srv_n_spin_wait_rounds>
 1092201:	jb     109203d <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x2d>
 1092207:	mov    0xe33062(%rip),%rdx        # 1ec5270 <sync_array_size>
 109220e:	addq   $0x1,-0x48(%rbp)
 1092213:	movq   $0x0,-0x40(%rbp)
 109221b:	test   %rdx,%rdx
 109221e:	je     1092295 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x285>
 1092220:	xor    %r12d,%r12d
 1092223:	jmp    1092283 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x273>
 1092225:	nopl   (%rax)
 1092228:	mov    0xe33031(%rip),%r13        # 1ec5260 <sync_wait_array>
 109222f:	callq  12e0670 <my_timer_cycles>
 1092234:	test   %rax,%rax
 1092237:	jne    109223e <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x22e>
 1092239:	callq  fda000 <_Z21os_thread_get_curr_idv>
 109223e:	xor    %edx,%edx
 1092240:	divq   0xe33029(%rip)        # 1ec5270 <sync_array_size>
 1092247:	mov    0x0(%r13,%rdx,8),%r13
 109224c:	mov    $0x4,%edx
 1092251:	mov    %r14,%r8
 1092254:	mov    %r15,%rcx
 1092257:	mov    %rbx,%rsi
 109225a:	mov    %r13,%rdi
 109225d:	add    $0x1,%r12
 1092261:	callq  10901b0 <_Z23sync_array_reserve_cellP12sync_array_tPvmPKcm>
 1092266:	mov    0xe33003(%rip),%rdx        # 1ec5270 <sync_array_size>
 109226d:	mov    %rax,-0x40(%rbp)
 1092271:	cmp    %rdx,%r12
 1092274:	jae    1092168 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x158>
 109227a:	test   %rax,%rax
 109227d:	jne    1092171 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x161>
 1092283:	cmp    $0x1,%rdx
 1092287:	ja     1092228 <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x218>
 1092289:	mov    0xe32fd0(%rip),%rax        # 1ec5260 <sync_wait_array>
 1092290:	mov    (%rax),%r13
 1092293:	jmp    109224c <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x23c>
 1092295:	callq  773d58 <_ZL31sync_array_get_and_reserve_cellPvmPKcmPP11sync_cell_t.part.3>
 109229a:	lea    -0x40(%rbp),%rsi
 109229e:	mov    %r13,%rdi
 10922a1:	xor    %r12d,%r12d
 10922a4:	callq  1090510 <_Z21sync_array_wait_eventP12sync_array_tRP11sync_cell_t>
 10922a9:	jmpq   109203d <_Z19rw_lock_s_lock_spinP9rw_lock_tmPKcm+0x2d>
 10922ae:	xchg   %ax,%ax
