// TC_OUT
00000000007b8340 <_Z8acl_initb>:
  7b8340:	push   %rbp
  7b8341:	mov    %rsp,%rbp
  7b8344:	push   %r15
  7b8346:	mov    %edi,%r15d
  7b8349:	mov    $0xe0,%edi
  7b834e:	push   %r14
  7b8350:	push   %r13
  7b8352:	push   %r12
  7b8354:	push   %rbx
  7b8355:	sub    $0x28,%rsp
  7b8359:	callq  761ea0 <_Znwm@plt>
  7b835e:	mov    %rax,%rbx
  7b8361:	lea    0x1660124(%rip),%rax        # 1e1848c <key_memory_acl_cache>
  7b8368:	mov    $0x70,%edx
  7b836d:	lea    0x70(%rbx),%rdi
  7b8371:	movl   $0x0,0x4(%rbx)
  7b8378:	movl   $0x0,0x8(%rbx)
  7b837f:	movl   $0x100,0x18(%rbx)
  7b8386:	movq   $0x0,0x30(%rbx)
  7b838e:	mov    (%rax),%eax
  7b8390:	test   $0x1,%dil
  7b8394:	movq   $0x0,0x38(%rbx)
  7b839c:	mov    %eax,(%rbx)
  7b839e:	lea    -0xaf55(%rip),%rax        # 7ad450 <_ZL17acl_entry_get_keyP9acl_entryPmc>
  7b83a5:	mov    %rax,0x10(%rbx)
  7b83a9:	lea    0x6fdc50(%rip),%rax        # eb6000 <my_free>
  7b83b0:	mov    %rax,0x20(%rbx)
  7b83b4:	lea    0x16539e5(%rip),%rax        # 1e0bda0 <my_charset_utf8_bin>
  7b83bb:	mov    %rax,0x28(%rbx)
  7b83bf:	jne    7b85a0 <_Z8acl_initb+0x260>
  7b83c5:	test   $0x2,%dil
  7b83c9:	jne    7b85b8 <_Z8acl_initb+0x278>
  7b83cf:	test   $0x4,%dil
  7b83d3:	jne    7b8588 <_Z8acl_initb+0x248>
  7b83d9:	mov    %edx,%ecx
  7b83db:	xor    %eax,%eax
  7b83dd:	shr    $0x3,%ecx
  7b83e0:	test   $0x4,%dl
  7b83e3:	rep stos %rax,%es:(%rdi)
  7b83e6:	je     7b83f2 <_Z8acl_initb+0xb2>
  7b83e8:	movl   $0x0,(%rdi)
  7b83ee:	add    $0x4,%rdi
  7b83f2:	test   $0x2,%dl
  7b83f5:	je     7b8401 <_Z8acl_initb+0xc1>
  7b83f7:	xor    %ecx,%ecx
  7b83f9:	add    $0x2,%rdi
  7b83fd:	mov    %cx,-0x2(%rdi)
  7b8401:	and    $0x1,%edx
  7b8404:	je     7b8409 <_Z8acl_initb+0xc9>
  7b8406:	movb   $0x0,(%rdi)
  7b8409:	lea    0x1660314(%rip),%rax        # 1e18724 <key_hash_filo_lock>
  7b8410:	lea    0x40(%rbx),%r12
  7b8414:	mov    %r12,%rsi
  7b8417:	mov    (%rax),%edi
  7b8419:	callq  ed63e0 <pfs_init_mutex_v1>
  7b841e:	lea    0x171bc8b(%rip),%rsi        # 1ed40b0 <my_fast_mutexattr>
  7b8425:	mov    %r12,%rdi
  7b8428:	mov    %rax,0x68(%rbx)
  7b842c:	callq  762300 <pthread_mutex_init@plt>
  7b8431:	lea    0x1665b18(%rip),%rax        # 1e1df50 <acl_cache>
  7b8438:	lea    0x1665a61(%rip),%r13        # 1e1dea0 <LOCK_grant>
  7b843f:	mov    $0x800,%edi
  7b8444:	mov    0x15b5a15(%rip),%rsi        # 1d6de60 <_DYNAMIC+0x278>
  7b844b:	mov    %rbx,(%rax)
  7b844e:	lea    0x16601cb(%rip),%rax        # 1e18620 <key_rwlock_LOCK_grant>
  7b8455:	movl   $0x20,0x8(%r13)
  7b845d:	mov    (%rax),%r14d
  7b8460:	callq  763250 <_ZnamRKSt9nothrow_t@plt>
  7b8465:	test   %rax,%rax
  7b8468:	mov    %rax,0x0(%r13)
  7b846c:	je     7b84b0 <_Z8acl_initb+0x170>
  7b846e:	mov    0x8(%r13),%edx
  7b8472:	test   %edx,%edx
  7b8474:	je     7b84b0 <_Z8acl_initb+0x170>
  7b8476:	mov    %rax,%r12
  7b8479:	xor    %ebx,%ebx
  7b847b:	jmp    7b8484 <_Z8acl_initb+0x144>
  7b847d:	nopl   (%rax)
  7b8480:	mov    0x0(%r13),%r12
  7b8484:	mov    %ebx,%edx
  7b8486:	mov    %r14d,%edi
  7b8489:	add    $0x1,%ebx
  7b848c:	shl    $0x6,%rdx
  7b8490:	add    %rdx,%r12
  7b8493:	mov    %r12,%rsi
  7b8496:	callq  ed6420 <pfs_init_rwlock_v1>
  7b849b:	xor    %esi,%esi
  7b849d:	mov    %rax,0x38(%r12)
  7b84a2:	mov    %r12,%rdi
  7b84a5:	callq  762000 <pthread_rwlock_init@plt>
  7b84aa:	cmp    0x8(%r13),%ebx
  7b84ae:	jb     7b8480 <_Z8acl_initb+0x140>
  7b84b0:	lea    0x16659f9(%rip),%rax        # 1e1deb0 <rwlocks_initialized>
  7b84b7:	lea    0x15bd7c2(%rip),%rsi        # 1d75c80 <native_password_plugin_name>
  7b84be:	mov    $0x7,%edx
  7b84c3:	xor    %edi,%edi
  7b84c5:	movb   $0x1,(%rax)
  7b84c8:	callq  cb4af0 <_Z19plugin_lock_by_nameP3THDRK25st_mysql_const_lex_stringi>
  7b84cd:	lea    0x166597c(%rip),%rdx        # 1e1de50 <native_password_plugin>
  7b84d4:	test   %rax,%rax
  7b84d7:	mov    %rax,(%rdx)
  7b84da:	je     7b8570 <_Z8acl_initb+0x230>
  7b84e0:	xor    %eax,%eax
  7b84e2:	test   %r15b,%r15b
  7b84e5:	je     7b8500 <_Z8acl_initb+0x1c0>
  7b84e7:	add    $0x28,%rsp
  7b84eb:	pop    %rbx
  7b84ec:	pop    %r12
  7b84ee:	pop    %r13
  7b84f0:	pop    %r14
  7b84f2:	pop    %r15
  7b84f4:	pop    %rbp
  7b84f5:	retq   
  7b84f6:	nopw   %cs:0x0(%rax,%rax,1)
  7b8500:	mov    $0x3560,%edi
  7b8505:	callq  761ea0 <_Znwm@plt>
  7b850a:	mov    $0x1,%esi
  7b850f:	mov    %rax,%rdi
  7b8512:	mov    %rax,%rbx
  7b8515:	callq  c53030 <_ZN3THDC1Eb>
  7b851a:	test   %rbx,%rbx
  7b851d:	mov    %rbx,-0x40(%rbp)
  7b8521:	je     7b8570 <_Z8acl_initb+0x230>
  7b8523:	lea    -0x40(%rbp),%rax
  7b8527:	mov    %rbx,%rdi
  7b852a:	mov    %rax,0xe20(%rbx)
  7b8531:	callq  c4d890 <_ZN3THD13store_globalsEv>
  7b8536:	mov    -0x40(%rbp),%rdi
  7b853a:	callq  7b50a0 <_Z10acl_reloadP3THD>
  7b853f:	mov    -0x40(%rbp),%rdi
  7b8543:	mov    %eax,%ebx
  7b8545:	callq  c506a0 <_ZN3THD17release_resourcesEv>
  7b854a:	mov    -0x40(%rbp),%rdi
  7b854e:	mov    %ebx,%eax
  7b8550:	test   %rdi,%rdi
  7b8553:	je     7b84e7 <_Z8acl_initb+0x1a7>
  7b8555:	mov    (%rdi),%rdx
  7b8558:	mov    %eax,-0x44(%rbp)
  7b855b:	callq  *0x8(%rdx)
  7b855e:	mov    -0x44(%rbp),%eax
  7b8561:	add    $0x28,%rsp
  7b8565:	pop    %rbx
  7b8566:	pop    %r12
  7b8568:	pop    %r13
  7b856a:	pop    %r14
  7b856c:	pop    %r15
  7b856e:	pop    %rbp
  7b856f:	retq   
  7b8570:	add    $0x28,%rsp
  7b8574:	mov    $0x1,%eax
  7b8579:	pop    %rbx
  7b857a:	pop    %r12
  7b857c:	pop    %r13
  7b857e:	pop    %r14
  7b8580:	pop    %r15
  7b8582:	pop    %rbp
  7b8583:	retq   
  7b8584:	nopl   0x0(%rax)
  7b8588:	movl   $0x0,(%rdi)
  7b858e:	sub    $0x4,%edx
  7b8591:	add    $0x4,%rdi
  7b8595:	jmpq   7b83d9 <_Z8acl_initb+0x99>
  7b859a:	nopw   0x0(%rax,%rax,1)
  7b85a0:	lea    0x71(%rbx),%rdi
  7b85a4:	movb   $0x0,0x70(%rbx)
  7b85a8:	mov    $0x6f,%dl
  7b85aa:	test   $0x2,%dil
  7b85ae:	je     7b83cf <_Z8acl_initb+0x8f>
  7b85b4:	nopl   0x0(%rax)
  7b85b8:	xor    %esi,%esi
  7b85ba:	add    $0x2,%rdi
  7b85be:	sub    $0x2,%edx
  7b85c1:	mov    %si,-0x2(%rdi)
  7b85c5:	jmpq   7b83cf <_Z8acl_initb+0x8f>
  7b85ca:	mov    %rax,%r12
  7b85cd:	mov    %rbx,%rdi
  7b85d0:	callq  7625e0 <_ZdlPv@plt>
  7b85d5:	mov    %r12,%rdi
  7b85d8:	callq  762870 <_Unwind_Resume@plt>
  7b85dd:	jmp    7b85ca <_Z8acl_initb+0x28a>
  7b85df:	nop
