// TC_OUT
0000000000e753b0 <_Z10init_slavev>:
  e753b0:	push   %rbp
  e753b1:	lea    0xf1f088(%rip),%rsi        # 1d94440 <_ZL17all_slave_threads>
  e753b8:	lea    0x789114(%rip),%rdi        # 15fe4d3 <_ZZ27row_merge_drop_indexes_dictP5trx_tmE3sql+0x29d3>
  e753bf:	mov    $0x3,%edx
  e753c4:	mov    %rsp,%rbp
  e753c7:	push   %r15
  e753c9:	push   %r14
  e753cb:	push   %r13
  e753cd:	push   %r12
  e753cf:	push   %rbx
  e753d0:	sub    $0x38,%rsp
  e753d4:	callq  edda50 <pfs_register_thread_v1>
  e753d9:	lea    0xf1fa00(%rip),%rax        # 1d94de0 <PSI_server>
  e753e0:	lea    0xf1f039(%rip),%rsi        # 1d94420 <_ZL16all_slave_memory>
  e753e7:	mov    $0x1,%edx
  e753ec:	lea    0x7890e0(%rip),%rdi        # 15fe4d3 <_ZZ27row_merge_drop_indexes_dictP5trx_tmE3sql+0x29d3>
  e753f3:	mov    (%rax),%rax
  e753f6:	callq  *0x3c8(%rax)
  e753fc:	lea    0xfdb07d(%rip),%rbx        # 1e50480 <channel_map>
  e75403:	mov    0x40(%rbx),%r12
  e75407:	mov    0x40(%r12),%rsi
  e7540c:	test   %rsi,%rsi
  e7540f:	je     e75590 <_Z10init_slavev+0x1e0>
  e75415:	lea    -0x60(%rbp),%rdi
  e75419:	lea    0x4a3d68(%rip),%rcx        # 1319188 <log_10+0x9a8>
  e75420:	mov    $0x1e1,%r8d
  e75426:	mov    $0x1,%edx
  e7542b:	callq  edd680 <pfs_start_rwlock_wrwait_v1>
  e75430:	lea    0x8(%r12),%rdi
  e75435:	mov    %rax,%r13
  e75438:	callq  761d70 <pthread_rwlock_wrlock@plt>
  e7543d:	test   %r13,%r13
  e75440:	je     e7544c <_Z10init_slavev+0x9c>
  e75442:	mov    %eax,%esi
  e75444:	mov    %r13,%rdi
  e75447:	callq  ed8f00 <pfs_end_rwlock_wrwait_v1>
  e7544c:	lea    0xfd9eb5(%rip),%rdi        # 1e4f308 <_ZL15RPL_MASTER_INFO>
  e75453:	movb   $0x1,(%r12)
  e75458:	xor    %esi,%esi
  e7545a:	callq  762040 <pthread_key_create@plt>
  e7545f:	test   %eax,%eax
  e75461:	mov    %eax,%r12d
  e75464:	je     e75480 <_Z10init_slavev+0xd0>
  e75466:	mov    $0x1,%r12d
  e7546c:	add    $0x38,%rsp
  e75470:	mov    %r12d,%eax
  e75473:	pop    %rbx
  e75474:	pop    %r12
  e75476:	pop    %r13
  e75478:	pop    %r14
  e7547a:	pop    %r15
  e7547c:	pop    %rbp
  e7547d:	retq   
  e7547e:	xchg   %ax,%ax
  e75480:	lea    0xfbed09(%rip),%rax        # 1e34190 <opt_rli_repository_id>
  e75487:	mov    %rbx,%rcx
  e7548a:	mov    $0x3,%edx
  e7548f:	mov    (%rax),%rsi
  e75492:	lea    0xfbed07(%rip),%rax        # 1e341a0 <opt_mi_repository_id>
  e75499:	mov    (%rax),%rdi
  e7549c:	callq  e8a130 <_ZN16Rpl_info_factory25create_slave_info_objectsEjjiP16Multisource_info>
  e754a1:	test   %al,%al
  e754a3:	je     e754f8 <_Z10init_slavev+0x148>
  e754a5:	lea    0x74b454(%rip),%rdi        # 15c0900 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x276c>
  e754ac:	xor    %eax,%eax
  e754ae:	mov    $0x1,%r13d
  e754b4:	callq  be5b90 <_Z15sql_print_errorPKcz>
  e754b9:	mov    0x40(%rbx),%rbx
  e754bd:	mov    0x40(%rbx),%rdi
  e754c1:	movb   $0x0,(%rbx)
  e754c4:	test   %rdi,%rdi
  e754c7:	je     e754ce <_Z10init_slavev+0x11e>
  e754c9:	callq  eda9a0 <pfs_unlock_rwlock_v1>
  e754ce:	lea    0x8(%rbx),%rdi
  e754d2:	callq  7633b0 <pthread_rwlock_unlock@plt>
  e754d7:	test   %r13d,%r13d
  e754da:	je     e7546c <_Z10init_slavev+0xbc>
  e754dc:	lea    0x74b4e5(%rip),%rdi        # 15c09c8 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x2834>
  e754e3:	xor    %eax,%eax
  e754e5:	mov    $0x1,%r12d
  e754eb:	callq  be84a0 <_Z21sql_print_informationPKcz>
  e754f0:	jmpq   e7546c <_Z10init_slavev+0xbc>
  e754f5:	nopl   (%rax)
  e754f8:	mov    $0x3,%edi
  e754fd:	callq  e1d770 <_Z13get_gtid_mode19enum_gtid_mode_lock>
  e75502:	test   %eax,%eax
  e75504:	je     e7559f <_Z10init_slavev+0x1ef>
  e7550a:	lea    0xfa7ea7(%rip),%rax        # 1e1d3b8 <mts_parallel_option>
  e75511:	lea    0xfa7ec0(%rip),%r13        # 1e1d3d8 <opt_mts_slave_parallel_workers>
  e75518:	mov    (%rax),%rdx
  e7551b:	lea    0xfa7e9e(%rip),%rax        # 1e1d3c0 <opt_slave_preserve_commit_order>
  e75522:	mov    0x0(%r13),%rcx
  e75526:	cmpb   $0x0,(%rax)
  e75529:	je     e75578 <_Z10init_slavev+0x1c8>
  e7552b:	test   %ecx,%ecx
  e7552d:	jle    e75578 <_Z10init_slavev+0x1c8>
  e7552f:	test   %edx,%edx
  e75531:	je     e7569b <_Z10init_slavev+0x2eb>
  e75537:	lea    0xfa8292(%rip),%rax        # 1e1d7d0 <opt_bin_log>
  e7553e:	cmpb   $0x0,(%rax)
  e75541:	je     e7554f <_Z10init_slavev+0x19f>
  e75543:	lea    0xfa8146(%rip),%rax        # 1e1d690 <opt_log_slave_updates>
  e7554a:	cmpb   $0x0,(%rax)
  e7554d:	jne    e75578 <_Z10init_slavev+0x1c8>
  e7554f:	cmp    $0x1,%edx
  e75552:	jne    e75578 <_Z10init_slavev+0x1c8>
  e75554:	lea    0x74b40d(%rip),%rdx        # 15c0968 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x27d4>
  e7555b:	xor    %esi,%esi
  e7555d:	mov    $0xbd7,%edi
  e75562:	xor    %eax,%eax
  e75564:	callq  eb3d90 <my_error>
  e75569:	mov    $0x1,%r13d
  e7556f:	jmpq   e754b9 <_Z10init_slavev+0x109>
  e75574:	nopl   0x0(%rax)
  e75578:	lea    0xfa8131(%rip),%rax        # 1e1d6b0 <opt_skip_slave_start>
  e7557f:	cmpb   $0x0,(%rax)
  e75582:	je     e756f1 <_Z10init_slavev+0x341>
  e75588:	xor    %r13d,%r13d
  e7558b:	jmpq   e754b9 <_Z10init_slavev+0x109>
  e75590:	lea    0x8(%r12),%rdi
  e75595:	callq  761d70 <pthread_rwlock_wrlock@plt>
  e7559a:	jmpq   e7544c <_Z10init_slavev+0x9c>
  e7559f:	mov    0x10(%rbx),%rdi
  e755a3:	test   %rdi,%rdi
  e755a6:	je     e75835 <_Z10init_slavev+0x485>
  e755ac:	mov    %rdi,%rax
  e755af:	lea    0x8(%rbx),%rdx
  e755b3:	jmp    e755c4 <_Z10init_slavev+0x214>
  e755b5:	nopl   (%rax)
  e755b8:	mov    %rax,%rdx
  e755bb:	mov    0x10(%rax),%rax
  e755bf:	test   %rax,%rax
  e755c2:	je     e755d3 <_Z10init_slavev+0x223>
  e755c4:	mov    0x20(%rax),%r14d
  e755c8:	test   %r14d,%r14d
  e755cb:	jns    e755b8 <_Z10init_slavev+0x208>
  e755cd:	mov    0x18(%rax),%rax
  e755d1:	jmp    e755bf <_Z10init_slavev+0x20f>
  e755d3:	lea    0x8(%rbx),%rax
  e755d7:	cmp    %rax,%rdx
  e755da:	je     e756b5 <_Z10init_slavev+0x305>
  e755e0:	mov    0x20(%rdx),%r13d
  e755e4:	test   %r13d,%r13d
  e755e7:	jg     e756b5 <_Z10init_slavev+0x305>
  e755ed:	mov    0x40(%rdx),%r13
  e755f1:	nopl   0x0(%rax)
  e755f8:	test   %rdi,%rdi
  e755fb:	je     e756e5 <_Z10init_slavev+0x335>
  e75601:	mov    %rdi,%rdx
  e75604:	lea    0x8(%rbx),%rcx
  e75608:	jmp    e7561c <_Z10init_slavev+0x26c>
  e7560a:	nopw   0x0(%rax,%rax,1)
  e75610:	mov    %rdx,%rcx
  e75613:	mov    0x10(%rdx),%rdx
  e75617:	test   %rdx,%rdx
  e7561a:	je     e7562e <_Z10init_slavev+0x27e>
  e7561c:	mov    0x20(%rdx),%r9d
  e75620:	test   %r9d,%r9d
  e75623:	jns    e75610 <_Z10init_slavev+0x260>
  e75625:	mov    0x18(%rdx),%rdx
  e75629:	test   %rdx,%rdx
  e7562c:	jne    e7561c <_Z10init_slavev+0x26c>
  e7562e:	lea    0x8(%rbx),%rax
  e75632:	cmp    %rax,%rcx
  e75635:	je     e756e5 <_Z10init_slavev+0x335>
  e7563b:	mov    0x20(%rcx),%r8d
  e7563f:	lea    0x30(%rcx),%rdx
  e75643:	lea    0x850(%rbx),%rax
  e7564a:	test   %r8d,%r8d
  e7564d:	cmovle %rdx,%rax
  e75651:	cmp    %rax,%r13
  e75654:	je     e7550a <_Z10init_slavev+0x15a>
  e7565a:	mov    0x28(%r13),%rsi
  e7565e:	test   %rsi,%rsi
  e75661:	je     e756e0 <_Z10init_slavev+0x330>
  e75663:	cmpb   $0x0,0x2150(%rsi)
  e7566a:	je     e756e0 <_Z10init_slavev+0x330>
  e7566c:	add    $0x6cc,%rsi
  e75673:	lea    0x74b3de(%rip),%rdi        # 15c0a58 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x28c4>
  e7567a:	xor    %eax,%eax
  e7567c:	mov    %rsi,%rdx
  e7567f:	callq  be8180 <_Z17sql_print_warningPKcz>
  e75684:	mov    0x10(%rbx),%r14
  e75688:	mov    %r13,%rdi
  e7568b:	callq  763050 <_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base@plt>
  e75690:	mov    %r14,%rdi
  e75693:	mov    %rax,%r13
  e75696:	jmpq   e755f8 <_Z10init_slavev+0x248>
  e7569b:	lea    0x74b29e(%rip),%rdx        # 15c0940 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x27ac>
  e756a2:	xor    %esi,%esi
  e756a4:	mov    $0xbd7,%edi
  e756a9:	xor    %eax,%eax
  e756ab:	callq  eb3d90 <my_error>
  e756b0:	jmpq   e75569 <_Z10init_slavev+0x1b9>
  e756b5:	mov    %rdi,%rax
  e756b8:	lea    0x8(%rbx),%rdx
  e756bc:	jmp    e756ce <_Z10init_slavev+0x31e>
  e756be:	mov    %rax,%rdx
  e756c1:	mov    0x10(%rax),%rax
  e756c5:	test   %rax,%rax
  e756c8:	je     e75811 <_Z10init_slavev+0x461>
  e756ce:	mov    0x20(%rax),%r11d
  e756d2:	test   %r11d,%r11d
  e756d5:	jns    e756be <_Z10init_slavev+0x30e>
  e756d7:	mov    0x18(%rax),%rax
  e756db:	jmp    e756c5 <_Z10init_slavev+0x315>
  e756dd:	nopl   (%rax)
  e756e0:	mov    %rdi,%r14
  e756e3:	jmp    e75688 <_Z10init_slavev+0x2d8>
  e756e5:	lea    0x850(%rbx),%rax
  e756ec:	jmpq   e75651 <_Z10init_slavev+0x2a1>
  e756f1:	xor    %edi,%edi
  e756f3:	callq  e6a790 <_ZN16Multisource_info5beginE17enum_channel_type.constprop.221>
  e756f8:	mov    0x10(%rbx),%r15
  e756fc:	mov    %rax,%r14
  e756ff:	nop
  e75700:	test   %r15,%r15
  e75703:	je     e757ec <_Z10init_slavev+0x43c>
  e75709:	mov    %r15,%rdx
  e7570c:	lea    0x8(%rbx),%rcx
  e75710:	jmp    e75724 <_Z10init_slavev+0x374>
  e75712:	nopw   0x0(%rax,%rax,1)
  e75718:	mov    %rdx,%rcx
  e7571b:	mov    0x10(%rdx),%rdx
  e7571f:	test   %rdx,%rdx
  e75722:	je     e75734 <_Z10init_slavev+0x384>
  e75724:	mov    0x20(%rdx),%esi
  e75727:	test   %esi,%esi
  e75729:	jns    e75718 <_Z10init_slavev+0x368>
  e7572b:	mov    0x18(%rdx),%rdx
  e7572f:	test   %rdx,%rdx
  e75732:	jne    e75724 <_Z10init_slavev+0x374>
  e75734:	lea    0x8(%rbx),%rax
  e75738:	cmp    %rax,%rcx
  e7573b:	je     e757ec <_Z10init_slavev+0x43c>
  e75741:	lea    0x30(%rcx),%rdx
  e75745:	mov    0x20(%rcx),%ecx
  e75748:	lea    0x850(%rbx),%rax
  e7574f:	test   %ecx,%ecx
  e75751:	cmovle %rdx,%rax
  e75755:	cmp    %rax,%r14
  e75758:	je     e75588 <_Z10init_slavev+0x1d8>
  e7575e:	mov    0x28(%r14),%rdx
  e75762:	test   %rdx,%rdx
  e75765:	je     e757cf <_Z10init_slavev+0x41f>
  e75767:	cmpb   $0x0,0x794(%rdx)
  e7576e:	je     e757cf <_Z10init_slavev+0x41f>
  e75770:	mov    0x1cf0(%rdx),%rax
  e75777:	mov    0x0(%r13),%rcx
  e7577b:	mov    %rcx,0x3108(%rax)
  e75782:	lea    0xfa7aef(%rip),%rcx        # 1e1d278 <opt_mts_checkpoint_group>
  e75789:	mov    0x1cf0(%rdx),%rax
  e75790:	mov    (%rcx),%ecx
  e75792:	mov    %ecx,0x3134(%rax)
  e75798:	lea    0xfa7c19(%rip),%rax        # 1e1d3b8 <mts_parallel_option>
  e7579f:	cmpq   $0x0,(%rax)
  e757a3:	mov    0x1cf0(%rdx),%rax
  e757aa:	jne    e757e0 <_Z10init_slavev+0x430>
  e757ac:	movl   $0x0,0x32a0(%rax)
  e757b6:	xor    %esi,%esi
  e757b8:	mov    $0x3,%ecx
  e757bd:	mov    $0x1,%edi
  e757c2:	callq  e75100 <_Z19start_slave_threadsbbP11Master_infoi>
  e757c7:	test   %al,%al
  e757c9:	jne    e757f8 <_Z10init_slavev+0x448>
  e757cb:	mov    0x10(%rbx),%r15
  e757cf:	mov    %r14,%rdi
  e757d2:	callq  763050 <_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base@plt>
  e757d7:	mov    %rax,%r14
  e757da:	jmpq   e75700 <_Z10init_slavev+0x350>
  e757df:	nop
  e757e0:	movl   $0x1,0x32a0(%rax)
  e757ea:	jmp    e757b6 <_Z10init_slavev+0x406>
  e757ec:	lea    0x850(%rbx),%rax
  e757f3:	jmpq   e75755 <_Z10init_slavev+0x3a5>
  e757f8:	lea    0x74b1a9(%rip),%rdi        # 15c09a8 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x2814>
  e757ff:	xor    %eax,%eax
  e75801:	mov    $0x1,%r13d
  e75807:	callq  be5b90 <_Z15sql_print_errorPKcz>
  e7580c:	jmpq   e754b9 <_Z10init_slavev+0x109>
  e75811:	lea    0x8(%rbx),%rax
  e75815:	cmp    %rax,%rdx
  e75818:	je     e75835 <_Z10init_slavev+0x485>
  e7581a:	mov    0x20(%rdx),%r10d
  e7581e:	lea    0x30(%rdx),%rax
  e75822:	lea    0x850(%rbx),%r13
  e75829:	test   %r10d,%r10d
  e7582c:	cmovle %rax,%r13
  e75830:	jmpq   e755f8 <_Z10init_slavev+0x248>
  e75835:	lea    0x850(%rbx),%r13
  e7583c:	jmpq   e755f8 <_Z10init_slavev+0x248>
  e75841:	data32 data32 data32 data32 data32 nopw %cs:0x0(%rax,%rax,1)
