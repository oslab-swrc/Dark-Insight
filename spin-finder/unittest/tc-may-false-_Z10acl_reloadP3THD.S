00000000007b50a0 <_Z10acl_reloadP3THD>:
  7b50a0:	push   %rbp
  7b50a1:	mov    %rsp,%rbp
  7b50a4:	push   %r15
  7b50a6:	lea    -0x2280(%rbp),%r15
  7b50ad:	push   %r14
  7b50af:	mov    %rdi,%r14
  7b50b2:	push   %r13
  7b50b4:	lea    0x12e8(%r15),%r13
  7b50bb:	push   %r12
  7b50bd:	lea    0x268(%r15),%r12
  7b50c4:	push   %rbx
  7b50c5:	lea    0x368(%r15),%rbx
  7b50cc:	sub    $0x24a8,%rsp
  7b50d3:	mov    %rbx,-0x2418(%rbp)
  7b50da:	mov    %fs:0x28,%rax
  7b50e3:	mov    %rax,-0x38(%rbp)
  7b50e7:	xor    %eax,%eax
  7b50e9:	mov    %rbx,%rdx
  7b50ec:	sub    -0x2418(%rbp),%rdx
  7b50f3:	mov    %r12,%rdi
  7b50f6:	add    $0x580,%rbx
  7b50fd:	movq   $0x0,0xc8(%r15,%rdx,1)
  7b5109:	callq  d26e70 <_ZN10GRANT_INFOC1Ev>
  7b510e:	lea    0x167713b(%rip),%rax        # 1e2c250 <end_of_list>
  7b5115:	lea    0x100(%r12),%rdx
  7b511d:	add    $0x580,%r12
  7b5124:	movl   $0x0,-0x570(%rbx)
  7b512e:	mov    %rdx,-0x578(%rbx)
  7b5135:	mov    %rax,-0x580(%rbx)
  7b513c:	cmp    %r13,%r12
  7b513f:	jne    7b50e9 <_Z10acl_reloadP3THD+0x49>
  7b5141:	xor    %r13d,%r13d
  7b5144:	mov    $0xb0,%ecx
  7b5149:	mov    %r15,%rdi
  7b514c:	mov    %r13,%rax
  7b514f:	lea    0x580(%r15),%r12
  7b5156:	lea    0xb60359(%rip),%rdx        # 13154b6 <_IO_stdin_used+0x276>
  7b515d:	rep stos %rax,%es:(%rdi)
  7b5160:	lea    0xb6034f(%rip),%rax        # 13154b6 <_IO_stdin_used+0x276>
  7b5167:	lea    0x398(%r15),%rdi
  7b516e:	lea    0xd870e5(%rip),%rcx        # 153c25a <_ZTS19Sql_cmd_drop_server+0x8a>
  7b5175:	mov    $0x1,%r9d
  7b517b:	mov    $0x3,%r8d
  7b5181:	mov    $0x3,%esi
  7b5186:	mov    %rax,-0x2268(%rbp)
  7b518d:	lea    0xd870c6(%rip),%rax        # 153c25a <_ZTS19Sql_cmd_drop_server+0x8a>
  7b5194:	movl   $0x6d0,0x8(%rsp)
  7b519c:	movq   $0x1,-0x2218(%rbp)
  7b51a7:	movq   $0x5,-0x1fc0(%rbp)
  7b51b2:	lea    0xb00(%r15),%rbx
  7b51b9:	mov    %rax,-0x2260(%rbp)
  7b51c0:	mov    %rax,-0x2258(%rbp)
  7b51c7:	lea    0xb6a6b2(%rip),%rax        # 131f880 <_ZTS32Find_thd_by_id_with_callback_setItE+0x3e0>
  7b51ce:	movq   $0x4,-0x1fb8(%rbp)
  7b51d9:	movl   $0x2,-0x1fd0(%rbp)
  7b51e3:	mov    %rax,(%rsp)
  7b51e7:	callq  be9ad0 <_ZN11MDL_request16init_with_sourceEN7MDL_key18enum_mdl_namespaceEPKcS3_13enum_mdl_type17enum_mdl_durationS3_j>
  7b51ec:	mov    %r13,%rax
  7b51ef:	mov    $0xb0,%ecx
  7b51f4:	mov    %r12,%rdi
  7b51f7:	rep stos %rax,%es:(%rdi)
  7b51fa:	lea    0xb602b5(%rip),%rax        # 13154b6 <_IO_stdin_used+0x276>
  7b5201:	lea    0x918(%r15),%rdi
  7b5208:	lea    0xb62863(%rip),%rcx        # 1317a72 <_IO_stdin_used+0x2832>
  7b520f:	lea    0xb602a0(%rip),%rdx        # 13154b6 <_IO_stdin_used+0x276>
  7b5216:	mov    $0x1,%r9d
  7b521c:	mov    $0x3,%r8d
  7b5222:	mov    %rax,-0x1ce8(%rbp)
  7b5229:	lea    0xb62842(%rip),%rax        # 1317a72 <_IO_stdin_used+0x2832>
  7b5230:	mov    $0x3,%esi
  7b5235:	movl   $0x6d0,0x8(%rsp)
  7b523d:	movq   $0x0,-0x1fd8(%rbp)
  7b5248:	mov    %rax,-0x1ce0(%rbp)
  7b524f:	mov    %rax,-0x1cd8(%rbp)
  7b5256:	lea    0xb6a623(%rip),%rax        # 131f880 <_ZTS32Find_thd_by_id_with_callback_setItE+0x3e0>
  7b525d:	movq   $0x0,-0x2230(%rbp)
  7b5268:	movq   $0x0,-0x2228(%rbp)
  7b5273:	mov    %rax,(%rsp)
  7b5277:	movq   $0x1,-0x1c98(%rbp)
  7b5282:	movq   $0x5,-0x1a40(%rbp)
  7b528d:	movq   $0x2,-0x1a38(%rbp)
  7b5298:	movl   $0x2,-0x1a50(%rbp)
  7b52a2:	callq  be9ad0 <_ZN11MDL_request16init_with_sourceEN7MDL_key18enum_mdl_namespaceEPKcS3_13enum_mdl_type17enum_mdl_durationS3_j>
  7b52a7:	mov    %r13,%rax
  7b52aa:	mov    $0xb0,%ecx
  7b52af:	mov    %rbx,%rdi
  7b52b2:	rep stos %rax,%es:(%rdi)
  7b52b5:	lea    0xb601fa(%rip),%rax        # 13154b6 <_IO_stdin_used+0x276>
  7b52bc:	lea    0xe98(%r15),%rdi
  7b52c3:	lea    0xb6a4fa(%rip),%rcx        # 131f7c4 <_ZTS32Find_thd_by_id_with_callback_setItE+0x324>
  7b52ca:	lea    0xb601e5(%rip),%rdx        # 13154b6 <_IO_stdin_used+0x276>
  7b52d1:	mov    $0x1,%r9d
  7b52d7:	mov    $0x3,%r8d
  7b52dd:	mov    %rax,-0x1768(%rbp)
  7b52e4:	lea    0xb6a4d9(%rip),%rax        # 131f7c4 <_ZTS32Find_thd_by_id_with_callback_setItE+0x324>
  7b52eb:	mov    $0x3,%esi
  7b52f0:	movl   $0x6d0,0x8(%rsp)
  7b52f8:	movq   $0x0,-0x1a58(%rbp)
  7b5303:	mov    %rax,-0x1760(%rbp)
  7b530a:	mov    %rax,-0x1758(%rbp)
  7b5311:	lea    0xb6a568(%rip),%rax        # 131f880 <_ZTS32Find_thd_by_id_with_callback_setItE+0x3e0>
  7b5318:	movq   $0x0,-0x1cb0(%rbp)
  7b5323:	movq   $0x0,-0x1ca8(%rbp)
  7b532e:	mov    %rax,(%rsp)
  7b5332:	movq   $0x1,-0x1718(%rbp)
  7b533d:	movq   $0x5,-0x14c0(%rbp)
  7b5348:	movq   $0xc,-0x14b8(%rbp)
  7b5353:	movl   $0x2,-0x14d0(%rbp)
  7b535d:	callq  be9ad0 <_ZN11MDL_request16init_with_sourceEN7MDL_key18enum_mdl_namespaceEPKcS3_13enum_mdl_type17enum_mdl_durationS3_j>
  7b5362:	lea    0x15928f7(%rip),%rax        # 1d47c60 <_ZTV23DML_prelocking_strategy>
  7b5369:	mov    $0x800,%edx
  7b536e:	mov    %r15,%rsi
  7b5371:	mov    %r14,%rdi
  7b5374:	movq   $0x0,-0x14d8(%rbp)
  7b537f:	movq   $0x0,-0x1730(%rbp)
  7b538a:	movq   $0x0,-0x1728(%rbp)
  7b5395:	mov    %r12,-0x2278(%rbp)
  7b539c:	add    $0x10,%rax
  7b53a0:	mov    %r12,-0x2280(%rbp)
  7b53a7:	mov    %rbx,-0x1cf8(%rbp)
  7b53ae:	mov    %rax,-0x2320(%rbp)
  7b53b5:	lea    -0x2320(%rbp),%rax
  7b53bc:	mov    %rbx,-0x1d00(%rbp)
  7b53c3:	movl   $0x2,-0x147c(%rbp)
  7b53cd:	movl   $0x2,-0x19fc(%rbp)
  7b53d7:	mov    %rax,%rcx
  7b53da:	movl   $0x2,-0x1f7c(%rbp)
  7b53e4:	movl   $0x1,-0x1458(%rbp)
  7b53ee:	mov    %rax,-0x2420(%rbp)
  7b53f5:	callq  c42070 <_Z20open_and_lock_tablesP3THDP10TABLE_LISTjP19Prelocking_strategy>
  7b53fa:	test   %al,%al
  7b53fc:	je     7b5448 <_Z10acl_reloadP3THD+0x3a8>
  7b53fe:	mov    0x3478(%r14),%rsi
  7b5405:	cmpl   $0x3,0x94(%rsi)
  7b540c:	je     7b5be0 <_Z10acl_reloadP3THD+0xb40>
  7b5412:	mov    %r14,%rdi
  7b5415:	callq  7bb100 <_Z16close_acl_tablesP3THD>
  7b541a:	mov    $0x1,%eax
  7b541f:	mov    -0x38(%rbp),%rcx
  7b5423:	xor    %fs:0x28,%rcx
  7b542c:	jne    7b7ca8 <_Z10acl_reloadP3THD+0x2c08>
  7b5432:	add    $0x24a8,%rsp
  7b5439:	pop    %rbx
  7b543a:	pop    %r12
  7b543c:	pop    %r13
  7b543e:	pop    %r14
  7b5440:	pop    %r15
  7b5442:	pop    %rbp
  7b5443:	retq   
  7b5444:	nopl   0x0(%rax)
  7b5448:	lea    0x1668a71(%rip),%rax        # 1e1dec0 <initialized>
  7b544f:	movzbl (%rax),%eax
  7b5452:	mov    %al,-0x2425(%rbp)
  7b5458:	test   %al,%al
  7b545a:	lea    0x1668aef(%rip),%rax        # 1e1df50 <acl_cache>
  7b5461:	mov    %rax,-0x2450(%rbp)
  7b5468:	jne    7b5b90 <_Z10acl_reloadP3THD+0xaf0>
  7b546e:	lea    0x1668c8b(%rip),%rax        # 1e1e100 <acl_users>
  7b5475:	mov    $0x8e0,%edi
  7b547a:	mov    (%rax),%rax
  7b547d:	mov    %rax,-0x2448(%rbp)
  7b5484:	lea    0x1668c55(%rip),%rax        # 1e1e0e0 <acl_dbs>
  7b548b:	mov    (%rax),%rax
  7b548e:	mov    %rax,-0x2438(%rbp)
  7b5495:	lea    0x1668c54(%rip),%rax        # 1e1e0f0 <acl_proxy_users>
  7b549c:	mov    (%rax),%rax
  7b549f:	mov    %rax,-0x2440(%rbp)
  7b54a6:	callq  761ea0 <_Znwm@plt>
  7b54ab:	lea    0x1662fe2(%rip),%rbx        # 1e18494 <key_memory_acl_mem>
  7b54b2:	lea    0x10(%rax),%rcx
  7b54b6:	mov    $0x2a0,%edi
  7b54bb:	movq   $0xa,0x8(%rax)
  7b54c3:	mov    %rcx,0x8d0(%rax)
  7b54ca:	lea    0x1668c2f(%rip),%rcx        # 1e1e100 <acl_users>
  7b54d1:	mov    (%rbx),%edx
  7b54d3:	movq   $0x0,(%rax)
  7b54da:	mov    %rax,(%rcx)
  7b54dd:	mov    %edx,0x8d8(%rax)
  7b54e3:	callq  761ea0 <_Znwm@plt>
  7b54e8:	lea    0x10(%rax),%rcx
  7b54ec:	mov    (%rbx),%edx
  7b54ee:	movq   $0xa,0x8(%rax)
  7b54f6:	movq   $0x0,(%rax)
  7b54fd:	mov    $0x430,%edi
  7b5502:	mov    %rcx,0x290(%rax)
  7b5509:	lea    0x1668bd0(%rip),%rcx        # 1e1e0e0 <acl_dbs>
  7b5510:	mov    %edx,0x298(%rax)
  7b5516:	mov    %rax,(%rcx)
  7b5519:	callq  761ea0 <_Znwm@plt>
  7b551e:	lea    0x10(%rax),%rcx
  7b5522:	lea    0x1668c57(%rip),%r15        # 1e1e180 <global_acl_memory>
  7b5529:	mov    (%rbx),%edx
  7b552b:	movq   $0xa,0x8(%rax)
  7b5533:	movq   $0x0,(%rax)
  7b553a:	mov    %rcx,0x420(%rax)
  7b5541:	lea    0x1668ba8(%rip),%rcx        # 1e1e0f0 <acl_proxy_users>
  7b5548:	mov    %edx,0x428(%rax)
  7b554e:	lea    0x1668b7b(%rip),%r12        # 1e1e0d0 <acl_wild_hosts>
  7b5555:	mov    %rax,(%rcx)
  7b5558:	mov    (%r15),%rax
  7b555b:	mov    (%r12),%r13
  7b555f:	mov    %rax,-0x23f0(%rbp)
  7b5566:	mov    0x8(%r15),%rax
  7b556a:	test   %r13,%r13
  7b556d:	mov    %rax,-0x23e8(%rbp)
  7b5574:	mov    0x10(%r15),%rax
  7b5578:	mov    %rax,-0x23e0(%rbp)
  7b557f:	mov    0x18(%r15),%rax
  7b5583:	mov    %rax,-0x23d8(%rbp)
  7b558a:	mov    0x20(%r15),%rax
  7b558e:	mov    %rax,-0x23d0(%rbp)
  7b5595:	mov    0x28(%r15),%rax
  7b5599:	mov    %rax,-0x23c8(%rbp)
  7b55a0:	mov    0x30(%r15),%rax
  7b55a4:	mov    %rax,-0x23c0(%rbp)
  7b55ab:	mov    0x38(%r15),%rax
  7b55af:	mov    %rax,-0x23b8(%rbp)
  7b55b6:	mov    0x40(%r15),%rax
  7b55ba:	mov    %rax,-0x23b0(%rbp)
  7b55c1:	mov    0x48(%r15),%rax
  7b55c5:	mov    %rax,-0x23a8(%rbp)
  7b55cc:	mov    0x50(%r15),%rax
  7b55d0:	mov    %rax,-0x23a0(%rbp)
  7b55d7:	je     7b55f6 <_Z10acl_reloadP3THD+0x556>
  7b55d9:	mov    0x150(%r13),%rdi
  7b55e0:	lea    0x10(%r13),%rax
  7b55e4:	cmp    %rax,%rdi
  7b55e7:	je     7b55ee <_Z10acl_reloadP3THD+0x54e>
  7b55e9:	callq  eb6000 <my_free>
  7b55ee:	mov    %r13,%rdi
  7b55f1:	callq  7625e0 <_ZdlPv@plt>
  7b55f6:	lea    0x16688e3(%rip),%rdi        # 1e1dee0 <acl_check_hosts>
  7b55fd:	movq   $0x0,(%r12)
  7b5605:	callq  e9bb50 <my_hash_free>
  7b560a:	lea    0x1667cf7(%rip),%rax        # 1e1d308 <specialflag>
  7b5611:	mov    (%rax),%rax
  7b5614:	mov    %rax,-0x2418(%rbp)
  7b561b:	mov    0x398(%r14),%rax
  7b5622:	mov    %rax,%rcx
  7b5625:	mov    %rax,-0x2460(%rbp)
  7b562c:	lea    0x14eecad(%rip),%rax        # 1ca42e0 <_ZTV34Acl_load_user_table_schema_factory>
  7b5633:	add    $0x10,%rax
  7b5637:	mov    %rax,-0x2400(%rbp)
  7b563e:	movabs $0xffffffff7fffffff,%rax
  7b5648:	and    %rcx,%rax
  7b564b:	mov    %rax,0x398(%r14)
  7b5652:	lea    0x166885b(%rip),%rax        # 1e1deb4 <grant_version>
  7b5659:	addl   $0x1,(%rax)
  7b565c:	mov    -0x2450(%rbp),%rax
  7b5663:	mov    (%rax),%r12
  7b5666:	lea    0x70(%r12),%r13
  7b566b:	movq   $0x0,0x30(%r12)
  7b5674:	movq   $0x0,0x38(%r12)
  7b567d:	mov    %r13,%rdi
  7b5680:	callq  e9bb50 <my_hash_free>
  7b5685:	mov    (%r12),%eax
  7b5689:	mov    0x4(%r12),%r9d
  7b568e:	xor    %ecx,%ecx
  7b5690:	mov    0x18(%r12),%r8d
  7b5695:	mov    0x28(%r12),%rdx
  7b569a:	xor    %esi,%esi
  7b569c:	movl   $0x0,0x18(%rsp)
  7b56a4:	mov    %r13,%rdi
  7b56a7:	mov    %eax,0x20(%rsp)
  7b56ab:	mov    0x20(%r12),%rax
  7b56b0:	mov    %rax,0x10(%rsp)
  7b56b5:	mov    0x10(%r12),%rax
  7b56ba:	mov    %rax,0x8(%rsp)
  7b56bf:	mov    0x8(%r12),%eax
  7b56c4:	mov    %rax,(%rsp)
  7b56c8:	callq  e9ba90 <_my_hash_init>
  7b56cd:	mov    (%rbx),%edi
  7b56cf:	xor    %ecx,%ecx
  7b56d1:	mov    $0x400,%edx
  7b56d6:	mov    %r15,%rsi
  7b56d9:	callq  d36b30 <_Z14init_sql_allocjP11st_mem_rootmm>
  7b56de:	mov    -0x21c0(%rbp),%r12
  7b56e5:	mov    -0x2420(%rbp),%rdi
  7b56ec:	xor    %ecx,%ecx
  7b56ee:	movl   $0x0,(%rsp)
  7b56f5:	mov    $0x1,%r9d
  7b56fb:	mov    $0x1,%r8d
  7b5701:	mov    %r14,%rsi
  7b5704:	mov    %r12,%rdx
  7b5707:	callq  bfe770 <_Z16init_read_recordP11READ_RECORDP3THDP5TABLEP7QEP_TABibb>
  7b570c:	test   %al,%al
  7b570e:	je     7b5800 <_Z10acl_reloadP3THD+0x760>
  7b5714:	mov    -0x2460(%rbp),%rax
  7b571b:	mov    %rax,0x398(%r14)
  7b5722:	xor    %edi,%edi
  7b5724:	mov    $0x1,%ebx
  7b5729:	callq  7b19b0 <_Z8acl_freeb>
  7b572e:	lea    0x16689cb(%rip),%rax        # 1e1e100 <acl_users>
  7b5735:	mov    -0x2448(%rbp),%rcx
  7b573c:	mov    %rcx,(%rax)
  7b573f:	lea    0x166899a(%rip),%rax        # 1e1e0e0 <acl_dbs>
  7b5746:	mov    -0x2438(%rbp),%rcx
  7b574d:	mov    %rcx,(%rax)
  7b5750:	lea    0x1668999(%rip),%rax        # 1e1e0f0 <acl_proxy_users>
  7b5757:	mov    -0x2440(%rbp),%rcx
  7b575e:	mov    %rcx,(%rax)
  7b5761:	mov    -0x23f0(%rbp),%rax
  7b5768:	mov    %rax,(%r15)
  7b576b:	mov    -0x23e8(%rbp),%rax
  7b5772:	mov    %rax,0x8(%r15)
  7b5776:	mov    -0x23e0(%rbp),%rax
  7b577d:	mov    %rax,0x10(%r15)
  7b5781:	mov    -0x23d8(%rbp),%rax
  7b5788:	mov    %rax,0x18(%r15)
  7b578c:	mov    -0x23d0(%rbp),%rax
  7b5793:	mov    %rax,0x20(%r15)
  7b5797:	mov    -0x23c8(%rbp),%rax
  7b579e:	mov    %rax,0x28(%r15)
  7b57a2:	mov    -0x23c0(%rbp),%rax
  7b57a9:	mov    %rax,0x30(%r15)
  7b57ad:	mov    -0x23b8(%rbp),%rax
  7b57b4:	mov    %rax,0x38(%r15)
  7b57b8:	mov    -0x23b0(%rbp),%rax
  7b57bf:	mov    %rax,0x40(%r15)
  7b57c3:	mov    -0x23a8(%rbp),%rax
  7b57ca:	mov    %rax,0x48(%r15)
  7b57ce:	mov    -0x23a0(%rbp),%rax
  7b57d5:	mov    %rax,0x50(%r15)
  7b57d9:	callq  7b3bf0 <_ZL15init_check_hostv>
  7b57de:	cmpb   $0x0,-0x2425(%rbp)
  7b57e5:	jne    7b6540 <_Z10acl_reloadP3THD+0x14a0>
  7b57eb:	mov    %r14,%rdi
  7b57ee:	callq  7bb100 <_Z16close_acl_tablesP3THD>
  7b57f3:	mov    %ebx,%eax
  7b57f5:	jmpq   7b541f <_Z10acl_reloadP3THD+0x37f>
  7b57fa:	nopw   0x0(%rax,%rax,1)
  7b5800:	mov    (%r12),%rax
  7b5804:	mov    0x8(%r12),%rdi
  7b5809:	add    $0x1c0,%rax
  7b580f:	test   %rdi,%rdi
  7b5812:	mov    %rax,0x1a8(%r12)
  7b581a:	mov    %rax,0x1b0(%r12)
  7b5822:	je     7b5833 <_Z10acl_reloadP3THD+0x793>
  7b5824:	cmpb   $0x0,0x7ff(%r12)
  7b582d:	jne    7b5c20 <_Z10acl_reloadP3THD+0xb80>
  7b5833:	lea    0x16688c6(%rip),%rax        # 1e1e100 <acl_users>
  7b583a:	lea    -0x2400(%rbp),%rdi
  7b5841:	mov    %r12,%rsi
  7b5844:	mov    (%rax),%rax
  7b5847:	movq   $0x0,(%rax)
  7b584e:	callq  7b8fe0 <_ZN34Acl_load_user_table_schema_factory24is_old_user_table_schemaEP5TABLE>
  7b5853:	test   %al,%al
  7b5855:	mov    $0x8,%edi
  7b585a:	jne    7b5c00 <_Z10acl_reloadP3THD+0xb60>
  7b5860:	callq  761ea0 <_Znwm@plt>
  7b5865:	mov    %rax,%rbx
  7b5868:	lea    0x14ee731(%rip),%rax        # 1ca3fa0 <_ZTV34Acl_load_user_table_current_schema>
  7b586f:	add    $0x10,%rax
  7b5873:	mov    %rax,(%rbx)
  7b5876:	mov    -0x2418(%rbp),%r13
  7b587d:	lea    0xb69ef0(%rip),%rdi        # 131f774 <_ZTS32Find_thd_by_id_with_callback_setItE+0x2d4>
  7b5884:	mov    $0x8,%ecx
  7b5889:	movb   $0x0,-0x2458(%rbp)
  7b5890:	shr    $0x6,%r13
  7b5894:	mov    %r13d,%eax
  7b5897:	and    $0x1,%eax
  7b589a:	mov    %al,-0x2424(%rbp)
  7b58a0:	mov    0x38(%r12),%rax
  7b58a5:	mov    0x10(%rax),%rax
  7b58a9:	mov    0x38(%rax),%rsi
  7b58ad:	repz cmpsb %es:(%rdi),%ds:(%rsi)
  7b58af:	lea    -0x2410(%rbp),%rcx
  7b58b6:	setb   %al
  7b58b9:	seta   %dl
  7b58bc:	sub    %eax,%edx
  7b58be:	mov    %rcx,-0x2430(%rbp)
  7b58c5:	movsbl %dl,%eax
  7b58c8:	mov    %eax,-0x2470(%rbp)
  7b58ce:	lea    0x15c03cb(%rip),%rax        # 1d75ca0 <allow_all_hosts>
  7b58d5:	movb   $0x0,(%rax)
  7b58d8:	lea    -0x920(%rbp),%rax
  7b58df:	mov    %rax,-0x2418(%rbp)
  7b58e6:	add    $0x88,%rax
  7b58ec:	mov    %rax,-0x2468(%rbp)
  7b58f3:	lea    -0x2390(%rbp),%rax
  7b58fa:	mov    %rax,-0x2498(%rbp)
  7b5901:	nopl   0x0(%rax)
  7b5908:	mov    -0x2420(%rbp),%rdi
  7b590f:	callq  *-0x2308(%rbp)
  7b5915:	test   %eax,%eax
  7b5917:	jne    7b6570 <_Z10acl_reloadP3THD+0x14d0>
  7b591d:	mov    -0x2418(%rbp),%rdi
  7b5924:	xor    %eax,%eax
  7b5926:	mov    $0x1c,%ecx
  7b592b:	rep stos %rax,%es:(%rdi)
  7b592e:	movb   $0x1,-0x877(%rbp)
  7b5935:	mov    %rbx,%rdi
  7b5938:	mov    (%rbx),%rax
  7b593b:	mov    0x38(%r12),%r13
  7b5940:	callq  *(%rax)
  7b5942:	mov    %eax,%eax
  7b5944:	mov    %r15,%rdi
  7b5947:	mov    0x0(%r13,%rax,8),%rsi
  7b594c:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5951:	mov    -0x2418(%rbp),%rdi
  7b5958:	mov    %rax,%rsi
  7b595b:	callq  7af0d0 <_ZN15ACL_HOST_AND_IP15update_hostnameEPKc>
  7b5960:	mov    (%rbx),%rax
  7b5963:	mov    0x38(%r12),%r13
  7b5968:	mov    %rbx,%rdi
  7b596b:	callq  *0x8(%rax)
  7b596e:	mov    %eax,%eax
  7b5970:	mov    %r15,%rdi
  7b5973:	mov    0x0(%r13,%rax,8),%rsi
  7b5978:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b597d:	cmpb   $0x0,-0x2424(%rbp)
  7b5984:	mov    %rax,-0x8d8(%rbp)
  7b598b:	jne    7b5d18 <_Z10acl_reloadP3THD+0xc78>
  7b5991:	mov    (%r12),%rax
  7b5995:	mov    %rbx,%rdi
  7b5998:	mov    0x2b0(%rax),%r13d
  7b599f:	mov    (%rbx),%rax
  7b59a2:	callq  *0x148(%rax)
  7b59a8:	cmp    %eax,%r13d
  7b59ab:	jbe    7b65b0 <_Z10acl_reloadP3THD+0x1510>
  7b59b1:	mov    (%rbx),%rax
  7b59b4:	mov    0x38(%r12),%r13
  7b59b9:	mov    %rbx,%rdi
  7b59bc:	callq  *0x148(%rax)
  7b59c2:	mov    %eax,%eax
  7b59c4:	mov    %r15,%rdi
  7b59c7:	mov    0x0(%r13,%rax,8),%rsi
  7b59cc:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b59d1:	test   %rax,%rax
  7b59d4:	mov    %rax,-0x888(%rbp)
  7b59db:	je     7b6260 <_Z10acl_reloadP3THD+0x11c0>
  7b59e1:	mov    %rax,%rdi
  7b59e4:	callq  762340 <strlen@plt>
  7b59e9:	mov    %rax,-0x880(%rbp)
  7b59f0:	mov    (%rbx),%rax
  7b59f3:	mov    %rbx,%rdi
  7b59f6:	callq  *0x18(%rax)
  7b59f9:	mov    -0x2430(%rbp),%rdx
  7b5a00:	mov    %eax,%esi
  7b5a02:	mov    %r12,%rdi
  7b5a05:	callq  7bafc0 <_Z10get_accessP5TABLEjPj>
  7b5a0a:	mov    %rax,%rcx
  7b5a0d:	and    $0x1fffffff,%ecx
  7b5a13:	mov    %rcx,-0x8f8(%rbp)
  7b5a1a:	mov    (%r12),%rdx
  7b5a1e:	mov    0x2b0(%rdx),%edx
  7b5a24:	cmp    $0x1f,%edx
  7b5a27:	ja     7b5c30 <_Z10acl_reloadP3THD+0xb90>
  7b5a2d:	test   $0x10,%al
  7b5a2f:	mov    %rcx,%rax
  7b5a32:	je     7b5c3c <_Z10acl_reloadP3THD+0xb9c>
  7b5a38:	or     $0x600000,%rax
  7b5a3e:	mov    %rax,-0x8f8(%rbp)
  7b5a45:	mov    (%r12),%rdx
  7b5a49:	mov    0x2b0(%rdx),%edx
  7b5a4f:	cmp    $0x21,%edx
  7b5a52:	jbe    7b5c3c <_Z10acl_reloadP3THD+0xb9c>
  7b5a58:	cmp    $0x24,%edx
  7b5a5b:	jbe    7b5c90 <_Z10acl_reloadP3THD+0xbf0>
  7b5a61:	cmp    $0x25,%edx
  7b5a64:	jbe    7b5cb8 <_Z10acl_reloadP3THD+0xc18>
  7b5a6a:	cmp    $0x26,%edx
  7b5a6d:	jbe    7b5ce1 <_Z10acl_reloadP3THD+0xc41>
  7b5a73:	mov    -0x8d8(%rbp),%rdx
  7b5a7a:	mov    -0x920(%rbp),%rsi
  7b5a81:	xor    %eax,%eax
  7b5a83:	mov    $0x2,%edi
  7b5a88:	callq  7af9f0 <_Z8get_sortjz>
  7b5a8d:	mov    %rax,-0x900(%rbp)
  7b5a94:	mov    (%r12),%rax
  7b5a98:	cmpl   $0x1e,0x2b0(%rax)
  7b5a9f:	ja     7b5d68 <_Z10acl_reloadP3THD+0xcc8>
  7b5aa5:	movl   $0x0,-0x8b8(%rbp)
  7b5aaf:	mov    (%r12),%rax
  7b5ab3:	cmpl   $0xd,0x2b0(%rax)
  7b5aba:	mov    -0x8f8(%rbp),%rax
  7b5ac1:	ja     7b5aca <_Z10acl_reloadP3THD+0xa2a>
  7b5ac3:	test   $0x10,%al
  7b5ac5:	je     7b5aca <_Z10acl_reloadP3THD+0xa2a>
  7b5ac7:	or     $0x38,%ah
  7b5aca:	test   $0x2,%ah
  7b5acd:	jne    7b5d00 <_Z10acl_reloadP3THD+0xc60>
  7b5ad3:	or     $0x34000,%rax
  7b5ad9:	mov    %rax,-0x8f8(%rbp)
  7b5ae0:	xor    %r13d,%r13d
  7b5ae3:	test   $0x1,%ah
  7b5ae6:	je     7b5af5 <_Z10acl_reloadP3THD+0xa55>
  7b5ae8:	or     $0x48000,%rax
  7b5aee:	mov    %rax,-0x8f8(%rbp)
  7b5af5:	mov    -0x2418(%rbp),%rdi
  7b5afc:	callq  7b1940 <_Z13set_user_saltP8ACL_USER>
  7b5b01:	lea    0x16685f8(%rip),%rax        # 1e1e100 <acl_users>
  7b5b08:	mov    %r13b,-0x878(%rbp)
  7b5b0f:	mov    (%rax),%r13
  7b5b12:	mov    0x0(%r13),%rax
  7b5b16:	cmp    0x8(%r13),%rax
  7b5b1a:	je     7b60a8 <_Z10acl_reloadP3THD+0x1008>
  7b5b20:	mov    0x8d0(%r13),%rcx
  7b5b27:	lea    0x1(%rax),%rdx
  7b5b2b:	mov    %rdx,0x0(%r13)
  7b5b2f:	mov    %rax,%rdx
  7b5b32:	shl    $0x8,%rax
  7b5b36:	shl    $0x5,%rdx
  7b5b3a:	sub    %rdx,%rax
  7b5b3d:	add    %rcx,%rax
  7b5b40:	je     7b5b54 <_Z10acl_reloadP3THD+0xab4>
  7b5b42:	mov    $0x1c,%ecx
  7b5b47:	mov    %rax,%rdi
  7b5b4a:	mov    -0x2418(%rbp),%rsi
  7b5b51:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b5b54:	mov    -0x920(%rbp),%rax
  7b5b5b:	test   %rax,%rax
  7b5b5e:	je     7b5b7c <_Z10acl_reloadP3THD+0xadc>
  7b5b60:	lea    0x15dec19(%rip),%rdx        # 1d94780 <wild_many>
  7b5b67:	movzbl (%rdx),%ecx
  7b5b6a:	cmp    %cl,(%rax)
  7b5b6c:	jne    7b5908 <_Z10acl_reloadP3THD+0x868>
  7b5b72:	cmpb   $0x0,0x1(%rax)
  7b5b76:	jne    7b5908 <_Z10acl_reloadP3THD+0x868>
  7b5b7c:	lea    0x15c011d(%rip),%rax        # 1d75ca0 <allow_all_hosts>
  7b5b83:	movb   $0x1,(%rax)
  7b5b86:	jmpq   7b5908 <_Z10acl_reloadP3THD+0x868>
  7b5b8b:	nopl   0x0(%rax,%rax,1)
  7b5b90:	mov    (%rax),%rbx
  7b5b93:	mov    0x68(%rbx),%rsi
  7b5b97:	test   %rsi,%rsi
  7b5b9a:	je     7b684b <_Z10acl_reloadP3THD+0x17ab>
  7b5ba0:	mov    -0x2420(%rbp),%rdi
  7b5ba7:	lea    0xb69c9a(%rip),%rcx        # 131f848 <_ZTS32Find_thd_by_id_with_callback_setItE+0x3a8>
  7b5bae:	xor    %edx,%edx
  7b5bb0:	mov    $0x816,%r8d
  7b5bb6:	callq  ed78e0 <pfs_start_mutex_wait_v1>
  7b5bbb:	lea    0x40(%rbx),%rdi
  7b5bbf:	mov    %rax,%r12
  7b5bc2:	callq  7620e0 <pthread_mutex_lock@plt>
  7b5bc7:	test   %r12,%r12
  7b5bca:	je     7b546e <_Z10acl_reloadP3THD+0x3ce>
  7b5bd0:	mov    %eax,%esi
  7b5bd2:	mov    %r12,%rdi
  7b5bd5:	callq  ed8be0 <pfs_end_mutex_wait_v1>
  7b5bda:	jmpq   7b546e <_Z10acl_reloadP3THD+0x3ce>
  7b5bdf:	nop
  7b5be0:	lea    0xb69cc1(%rip),%rdi        # 131f8a8 <_ZTS32Find_thd_by_id_with_callback_setItE+0x408>
  7b5be7:	add    $0x98,%rsi
  7b5bee:	xor    %eax,%eax
  7b5bf0:	callq  be5b90 <_Z15sql_print_errorPKcz>
  7b5bf5:	jmpq   7b5412 <_Z10acl_reloadP3THD+0x372>
  7b5bfa:	nopw   0x0(%rax,%rax,1)
  7b5c00:	callq  761ea0 <_Znwm@plt>
  7b5c05:	mov    %rax,%rbx
  7b5c08:	lea    0x14ee531(%rip),%rax        # 1ca4140 <_ZTV30Acl_load_user_table_old_schema>
  7b5c0f:	add    $0x10,%rax
  7b5c13:	mov    %rax,(%rbx)
  7b5c16:	jmpq   7b5876 <_Z10acl_reloadP3THD+0x7d6>
  7b5c1b:	nopl   0x0(%rax,%rax,1)
  7b5c20:	mov    (%rdi),%rax
  7b5c23:	callq  *0xe0(%rax)
  7b5c29:	jmpq   7b5833 <_Z10acl_reloadP3THD+0x793>
  7b5c2e:	xchg   %ax,%ax
  7b5c30:	cmp    $0x21,%edx
  7b5c33:	mov    %rcx,%rax
  7b5c36:	ja     7b5a58 <_Z10acl_reloadP3THD+0x9b8>
  7b5c3c:	test   $0x10,%al
  7b5c3e:	xchg   %ax,%ax
  7b5c40:	je     7b5c62 <_Z10acl_reloadP3THD+0xbc2>
  7b5c42:	or     $0x800000,%rax
  7b5c48:	mov    %rax,-0x8f8(%rbp)
  7b5c4f:	mov    (%r12),%rdx
  7b5c53:	mov    0x2b0(%rdx),%edx
  7b5c59:	cmp    $0x21,%edx
  7b5c5c:	ja     7b5a58 <_Z10acl_reloadP3THD+0x9b8>
  7b5c62:	test   $0x20,%ah
  7b5c65:	je     7b5c90 <_Z10acl_reloadP3THD+0xbf0>
  7b5c67:	or     $0x1000000,%rax
  7b5c6d:	mov    %rax,-0x8f8(%rbp)
  7b5c74:	mov    (%r12),%rdx
  7b5c78:	mov    0x2b0(%rdx),%edx
  7b5c7e:	cmp    $0x24,%edx
  7b5c81:	ja     7b5a61 <_Z10acl_reloadP3THD+0x9c1>
  7b5c87:	nopw   0x0(%rax,%rax,1)
  7b5c90:	test   $0x4,%ah
  7b5c93:	je     7b5cb8 <_Z10acl_reloadP3THD+0xc18>
  7b5c95:	or     $0x2000000,%rax
  7b5c9b:	mov    %rax,-0x8f8(%rbp)
  7b5ca2:	mov    (%r12),%rdx
  7b5ca6:	mov    0x2b0(%rdx),%edx
  7b5cac:	cmp    $0x25,%edx
  7b5caf:	ja     7b5a6a <_Z10acl_reloadP3THD+0x9ca>
  7b5cb5:	nopl   (%rax)
  7b5cb8:	test   $0x80,%ah
  7b5cbb:	je     7b5a73 <_Z10acl_reloadP3THD+0x9d3>
  7b5cc1:	or     $0x4000000,%rax
  7b5cc7:	mov    %rax,-0x8f8(%rbp)
  7b5cce:	mov    (%r12),%rdx
  7b5cd2:	mov    0x2b0(%rdx),%edx
  7b5cd8:	cmp    $0x26,%edx
  7b5cdb:	ja     7b5a73 <_Z10acl_reloadP3THD+0x9d3>
  7b5ce1:	test   $0x80,%ah
  7b5ce4:	je     7b5a73 <_Z10acl_reloadP3THD+0x9d3>
  7b5cea:	or     $0x8000000,%rax
  7b5cf0:	mov    %rax,-0x8f8(%rbp)
  7b5cf7:	jmpq   7b5a73 <_Z10acl_reloadP3THD+0x9d3>
  7b5cfc:	nopl   0x0(%rax)
  7b5d00:	or     $0x1b4000,%rax
  7b5d06:	mov    %rax,-0x8f8(%rbp)
  7b5d0d:	jmpq   7b5ae0 <_Z10acl_reloadP3THD+0xa40>
  7b5d12:	nopw   0x0(%rax,%rax,1)
  7b5d18:	mov    -0x920(%rbp),%rdi
  7b5d1f:	callq  7afdc0 <_Z27hostname_requires_resolvingPKc>
  7b5d24:	test   %al,%al
  7b5d26:	je     7b5991 <_Z10acl_reloadP3THD+0x8f1>
  7b5d2c:	mov    -0x920(%rbp),%rdx
  7b5d33:	mov    -0x8d8(%rbp),%rsi
  7b5d3a:	lea    0xd76baf(%rip),%rax        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  7b5d41:	lea    0xb69d18(%rip),%rdi        # 131fa60 <_ZTS32Find_thd_by_id_with_callback_setItE+0x5c0>
  7b5d48:	test   %rdx,%rdx
  7b5d4b:	cmove  %rax,%rdx
  7b5d4f:	test   %rsi,%rsi
  7b5d52:	cmove  %rax,%rsi
  7b5d56:	xor    %eax,%eax
  7b5d58:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b5d5d:	jmpq   7b5991 <_Z10acl_reloadP3THD+0x8f1>
  7b5d62:	nopw   0x0(%rax,%rax,1)
  7b5d68:	mov    (%rbx),%rax
  7b5d6b:	mov    0x38(%r12),%r13
  7b5d70:	mov    %rbx,%rdi
  7b5d73:	callq  *0x100(%rax)
  7b5d79:	mov    %eax,%eax
  7b5d7b:	mov    0x18(%r14),%rdi
  7b5d7f:	mov    0x0(%r13,%rax,8),%rsi
  7b5d84:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5d89:	test   %rax,%rax
  7b5d8c:	je     7b6528 <_Z10acl_reloadP3THD+0x1488>
  7b5d92:	lea    0xb69a38(%rip),%rdi        # 131f7d1 <_ZTS32Find_thd_by_id_with_callback_setItE+0x331>
  7b5d99:	mov    $0x4,%ecx
  7b5d9e:	mov    %rax,%rsi
  7b5da1:	repz cmpsb %es:(%rdi),%ds:(%rsi)
  7b5da3:	jne    7b6288 <_Z10acl_reloadP3THD+0x11e8>
  7b5da9:	movl   $0x1,-0x8b8(%rbp)
  7b5db3:	mov    (%rbx),%rax
  7b5db6:	mov    0x38(%r12),%r13
  7b5dbb:	mov    %rbx,%rdi
  7b5dbe:	callq  *0x108(%rax)
  7b5dc4:	mov    %eax,%eax
  7b5dc6:	mov    %r15,%rdi
  7b5dc9:	mov    0x0(%r13,%rax,8),%rsi
  7b5dce:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5dd3:	mov    %rax,-0x8b0(%rbp)
  7b5dda:	mov    (%rbx),%rax
  7b5ddd:	mov    %rbx,%rdi
  7b5de0:	mov    0x38(%r12),%r13
  7b5de5:	callq  *0x110(%rax)
  7b5deb:	mov    %eax,%eax
  7b5ded:	mov    %r15,%rdi
  7b5df0:	mov    0x0(%r13,%rax,8),%rsi
  7b5df5:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5dfa:	mov    %rax,-0x8a8(%rbp)
  7b5e01:	mov    (%rbx),%rax
  7b5e04:	mov    %rbx,%rdi
  7b5e07:	mov    0x38(%r12),%r13
  7b5e0c:	callq  *0x118(%rax)
  7b5e12:	mov    %eax,%eax
  7b5e14:	mov    %r15,%rdi
  7b5e17:	mov    0x0(%r13,%rax,8),%rsi
  7b5e1c:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5e21:	mov    %rax,-0x8a0(%rbp)
  7b5e28:	mov    (%rbx),%rax
  7b5e2b:	mov    %rbx,%rdi
  7b5e2e:	mov    0x38(%r12),%r13
  7b5e33:	callq  *0x120(%rax)
  7b5e39:	mov    %eax,%eax
  7b5e3b:	mov    0x18(%r14),%rdi
  7b5e3f:	mov    0x0(%r13,%rax,8),%rsi
  7b5e44:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5e49:	xor    %edx,%edx
  7b5e4b:	test   %rax,%rax
  7b5e4e:	je     7b5e5e <_Z10acl_reloadP3THD+0xdbe>
  7b5e50:	mov    $0xa,%dl
  7b5e52:	xor    %esi,%esi
  7b5e54:	mov    %rax,%rdi
  7b5e57:	callq  762dc0 <strtol@plt>
  7b5e5c:	mov    %eax,%edx
  7b5e5e:	mov    %edx,-0x8f0(%rbp)
  7b5e64:	mov    (%rbx),%rax
  7b5e67:	mov    %rbx,%rdi
  7b5e6a:	mov    0x38(%r12),%r13
  7b5e6f:	callq  *0x128(%rax)
  7b5e75:	mov    %eax,%eax
  7b5e77:	mov    0x18(%r14),%rdi
  7b5e7b:	mov    0x0(%r13,%rax,8),%rsi
  7b5e80:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5e85:	xor    %edx,%edx
  7b5e87:	test   %rax,%rax
  7b5e8a:	je     7b5e9a <_Z10acl_reloadP3THD+0xdfa>
  7b5e8c:	mov    $0xa,%dl
  7b5e8e:	xor    %esi,%esi
  7b5e90:	mov    %rax,%rdi
  7b5e93:	callq  762dc0 <strtol@plt>
  7b5e98:	mov    %eax,%edx
  7b5e9a:	mov    %edx,-0x8ec(%rbp)
  7b5ea0:	mov    (%rbx),%rax
  7b5ea3:	mov    %rbx,%rdi
  7b5ea6:	mov    0x38(%r12),%r13
  7b5eab:	callq  *0x130(%rax)
  7b5eb1:	mov    %eax,%eax
  7b5eb3:	mov    0x18(%r14),%rdi
  7b5eb7:	mov    0x0(%r13,%rax,8),%rsi
  7b5ebc:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5ec1:	test   %rax,%rax
  7b5ec4:	je     7b80af <_Z10acl_reloadP3THD+0x300f>
  7b5eca:	xor    %esi,%esi
  7b5ecc:	mov    $0xa,%edx
  7b5ed1:	mov    %rax,%rdi
  7b5ed4:	callq  762dc0 <strtol@plt>
  7b5ed9:	cmpq   $0x0,-0x8f0(%rbp)
  7b5ee1:	mov    %eax,-0x8e8(%rbp)
  7b5ee7:	jne    7b5eed <_Z10acl_reloadP3THD+0xe4d>
  7b5ee9:	test   %eax,%eax
  7b5eeb:	je     7b5ef7 <_Z10acl_reloadP3THD+0xe57>
  7b5eed:	lea    0x166764d(%rip),%rax        # 1e1d541 <mqh_used>
  7b5ef4:	movb   $0x1,(%rax)
  7b5ef7:	mov    (%r12),%rax
  7b5efb:	mov    %rbx,%rdi
  7b5efe:	mov    0x2b0(%rax),%r13d
  7b5f05:	mov    (%rbx),%rax
  7b5f08:	callq  *0x138(%rax)
  7b5f0e:	cmp    %eax,%r13d
  7b5f11:	ja     7b62c0 <_Z10acl_reloadP3THD+0x1220>
  7b5f17:	mov    (%r12),%rax
  7b5f1b:	cmpl   $0x28,0x2b0(%rax)
  7b5f22:	jbe    7b61d8 <_Z10acl_reloadP3THD+0x1138>
  7b5f28:	mov    (%rbx),%rax
  7b5f2b:	mov    0x38(%r12),%r13
  7b5f30:	mov    %rbx,%rdi
  7b5f33:	callq  *0x140(%rax)
  7b5f39:	mov    %eax,%eax
  7b5f3b:	mov    %r15,%rdi
  7b5f3e:	mov    0x0(%r13,%rax,8),%rsi
  7b5f43:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5f48:	mov    -0x2470(%rbp),%edx
  7b5f4e:	mov    %rax,%r13
  7b5f51:	test   %edx,%edx
  7b5f53:	jne    7b6040 <_Z10acl_reloadP3THD+0xfa0>
  7b5f59:	test   %rax,%rax
  7b5f5c:	je     7b5f67 <_Z10acl_reloadP3THD+0xec7>
  7b5f5e:	cmpb   $0x0,(%rax)
  7b5f61:	jne    7b6620 <_Z10acl_reloadP3THD+0x1580>
  7b5f67:	lea    0x15bfd12(%rip),%rax        # 1d75c80 <native_password_plugin_name>
  7b5f6e:	mov    %rax,-0x2478(%rbp)
  7b5f75:	mov    0x38(%r12),%rdx
  7b5f7a:	mov    (%rbx),%rax
  7b5f7d:	mov    %rbx,%rdi
  7b5f80:	mov    %rdx,-0x2480(%rbp)
  7b5f87:	callq  *0x10(%rax)
  7b5f8a:	mov    -0x2480(%rbp),%rdx
  7b5f91:	mov    %eax,%eax
  7b5f93:	mov    %r15,%rdi
  7b5f96:	mov    (%rdx,%rax,8),%rsi
  7b5f9a:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b5f9f:	mov    -0x2478(%rbp),%rsi
  7b5fa6:	xor    %edi,%edi
  7b5fa8:	mov    $0x7,%edx
  7b5fad:	mov    %rax,-0x2480(%rbp)
  7b5fb4:	callq  cb4af0 <_Z19plugin_lock_by_nameP3THDRK25st_mysql_const_lex_stringi>
  7b5fb9:	test   %rax,%rax
  7b5fbc:	mov    %rax,%r8
  7b5fbf:	je     7b6040 <_Z10acl_reloadP3THD+0xfa0>
  7b5fc1:	mov    -0x2480(%rbp),%rdi
  7b5fc8:	test   %rdi,%rdi
  7b5fcb:	je     7b6859 <_Z10acl_reloadP3THD+0x17b9>
  7b5fd1:	mov    %r8,-0x2490(%rbp)
  7b5fd8:	callq  762340 <strlen@plt>
  7b5fdd:	mov    -0x2490(%rbp),%r8
  7b5fe4:	mov    %eax,-0x2488(%rbp)
  7b5fea:	mov    %eax,%esi
  7b5fec:	mov    0x10(%r8),%rax
  7b5ff0:	mov    %r8,-0x2490(%rbp)
  7b5ff7:	mov    -0x2480(%rbp),%rdi
  7b5ffe:	mov    0x8(%rax),%rax
  7b6002:	callq  *0x20(%rax)
  7b6005:	test   %eax,%eax
  7b6007:	mov    -0x2490(%rbp),%r8
  7b600e:	jne    7b6658 <_Z10acl_reloadP3THD+0x15b8>
  7b6014:	cmpq   $0x0,-0x880(%rbp)
  7b601c:	je     7b66cd <_Z10acl_reloadP3THD+0x162d>
  7b6022:	test   %r13,%r13
  7b6025:	je     7b66ed <_Z10acl_reloadP3THD+0x164d>
  7b602b:	cmpb   $0x0,0x0(%r13)
  7b6030:	je     7b66ed <_Z10acl_reloadP3THD+0x164d>
  7b6036:	mov    %r8,%rsi
  7b6039:	xor    %edi,%edi
  7b603b:	callq  cb6d60 <_Z13plugin_unlockP3THDP13st_plugin_int>
  7b6040:	test   %r13,%r13
  7b6043:	je     7b6050 <_Z10acl_reloadP3THD+0xfb0>
  7b6045:	cmpb   $0x0,0x0(%r13)
  7b604a:	jne    7b6188 <_Z10acl_reloadP3THD+0x10e8>
  7b6050:	testb  $0x80,-0x8f7(%rbp)
  7b6057:	movzbl -0x2458(%rbp),%ecx
  7b605e:	mov    $0x1,%eax
  7b6063:	mov    -0x920(%rbp),%rdx
  7b606a:	mov    -0x8d8(%rbp),%rsi
  7b6071:	lea    0xb69af0(%rip),%rdi        # 131fb68 <_ZTS32Find_thd_by_id_with_callback_setItE+0x6c8>
  7b6078:	cmovne %eax,%ecx
  7b607b:	lea    0xd7686e(%rip),%rax        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  7b6082:	test   %rdx,%rdx
  7b6085:	mov    %cl,-0x2458(%rbp)
  7b608b:	cmove  %rax,%rdx
  7b608f:	test   %rsi,%rsi
  7b6092:	cmove  %rax,%rsi
  7b6096:	xor    %eax,%eax
  7b6098:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b609d:	jmpq   7b5908 <_Z10acl_reloadP3THD+0x868>
  7b60a2:	nopw   0x0(%rax,%rax,1)
  7b60a8:	lea    (%rax,%rax,1),%r11
  7b60ac:	cmp    %r11,%rax
  7b60af:	jae    7b5b20 <_Z10acl_reloadP3THD+0xa80>
  7b60b5:	mov    %rax,%rdx
  7b60b8:	mov    0x8d8(%r13),%edi
  7b60bf:	shl    $0x9,%rax
  7b60c3:	shl    $0x6,%rdx
  7b60c7:	mov    %rax,%rsi
  7b60ca:	mov    %r11,-0x2478(%rbp)
  7b60d1:	sub    %rdx,%rsi
  7b60d4:	mov    $0x10,%edx
  7b60d9:	callq  eb5ec0 <my_malloc>
  7b60de:	test   %rax,%rax
  7b60e1:	mov    %rax,%r10
  7b60e4:	je     7b5b54 <_Z10acl_reloadP3THD+0xab4>
  7b60ea:	mov    0x0(%r13),%rax
  7b60ee:	xor    %r8d,%r8d
  7b60f1:	mov    0x8d0(%r13),%rdi
  7b60f8:	mov    %r10,%rdx
  7b60fb:	mov    $0x1c,%r9d
  7b6101:	mov    -0x2478(%rbp),%r11
  7b6108:	test   %rax,%rax
  7b610b:	je     7b6142 <_Z10acl_reloadP3THD+0x10a2>
  7b610d:	nopl   (%rax)
  7b6110:	mov    %rdx,%rsi
  7b6113:	sub    %r10,%rsi
  7b6116:	add    %rdi,%rsi
  7b6119:	test   %rdx,%rdx
  7b611c:	je     7b6132 <_Z10acl_reloadP3THD+0x1092>
  7b611e:	mov    %rdx,%rdi
  7b6121:	mov    %r9,%rcx
  7b6124:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b6127:	mov    0x8d0(%r13),%rdi
  7b612e:	mov    0x0(%r13),%rax
  7b6132:	add    $0x1,%r8
  7b6136:	add    $0xe0,%rdx
  7b613d:	cmp    %rax,%r8
  7b6140:	jb     7b6110 <_Z10acl_reloadP3THD+0x1070>
  7b6142:	lea    0x10(%r13),%rdx
  7b6146:	cmp    %rdx,%rdi
  7b6149:	je     7b6170 <_Z10acl_reloadP3THD+0x10d0>
  7b614b:	mov    %r10,-0x2480(%rbp)
  7b6152:	mov    %r11,-0x2478(%rbp)
  7b6159:	callq  eb6000 <my_free>
  7b615e:	mov    0x0(%r13),%rax
  7b6162:	mov    -0x2480(%rbp),%r10
  7b6169:	mov    -0x2478(%rbp),%r11
  7b6170:	mov    %r10,0x8d0(%r13)
  7b6177:	mov    %r11,0x8(%r13)
  7b617b:	mov    %r10,%rcx
  7b617e:	jmpq   7b5b27 <_Z10acl_reloadP3THD+0xa87>
  7b6183:	nopl   0x0(%rax,%rax,1)
  7b6188:	lea    0x1664b11(%rip),%rax        # 1e1aca0 <system_charset_info>
  7b618f:	lea    0x15bfaea(%rip),%rcx        # 1d75c80 <native_password_plugin_name>
  7b6196:	mov    %r13,%rsi
  7b6199:	mov    (%rax),%rdi
  7b619c:	mov    %rcx,-0x2478(%rbp)
  7b61a3:	mov    (%rcx),%rdx
  7b61a6:	mov    0xb8(%rdi),%rax
  7b61ad:	callq  *0x38(%rax)
  7b61b0:	test   %eax,%eax
  7b61b2:	jne    7b67e8 <_Z10acl_reloadP3THD+0x1748>
  7b61b8:	mov    -0x2478(%rbp),%rcx
  7b61bf:	mov    (%rcx),%rax
  7b61c2:	mov    0x8(%rcx),%rdx
  7b61c6:	mov    %rax,-0x898(%rbp)
  7b61cd:	mov    %rdx,-0x890(%rbp)
  7b61d4:	nopl   0x0(%rax)
  7b61d8:	mov    -0x2468(%rbp),%rsi
  7b61df:	xor    %edi,%edi
  7b61e1:	mov    $0x7,%edx
  7b61e6:	callq  cb4af0 <_Z19plugin_lock_by_nameP3THDRK25st_mysql_const_lex_stringi>
  7b61eb:	test   %rax,%rax
  7b61ee:	mov    %rax,%r13
  7b61f1:	je     7b6312 <_Z10acl_reloadP3THD+0x1272>
  7b61f7:	mov    0x10(%rax),%rax
  7b61fb:	mov    -0x880(%rbp),%esi
  7b6201:	mov    -0x888(%rbp),%rdi
  7b6208:	mov    0x8(%rax),%rax
  7b620c:	callq  *0x20(%rax)
  7b620f:	test   %eax,%eax
  7b6211:	je     7b6308 <_Z10acl_reloadP3THD+0x1268>
  7b6217:	mov    -0x920(%rbp),%rdx
  7b621e:	mov    -0x8d8(%rbp),%rsi
  7b6225:	lea    0xd766c4(%rip),%rax        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  7b622c:	lea    0xb699ad(%rip),%rdi        # 131fbe0 <_ZTS32Find_thd_by_id_with_callback_setItE+0x740>
  7b6233:	test   %rdx,%rdx
  7b6236:	cmove  %rax,%rdx
  7b623a:	test   %rsi,%rsi
  7b623d:	cmove  %rax,%rsi
  7b6241:	xor    %eax,%eax
  7b6243:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b6248:	mov    %r13,%rsi
  7b624b:	xor    %edi,%edi
  7b624d:	callq  cb6d60 <_Z13plugin_unlockP3THDP13st_plugin_int>
  7b6252:	jmpq   7b5908 <_Z10acl_reloadP3THD+0x868>
  7b6257:	nopw   0x0(%rax,%rax,1)
  7b6260:	lea    0x15ca939(%rip),%rax        # 1d80ba0 <EMPTY_STR>
  7b6267:	mov    0x8(%rax),%rdx
  7b626b:	mov    (%rax),%rax
  7b626e:	mov    %rdx,-0x880(%rbp)
  7b6275:	mov    %rax,-0x888(%rbp)
  7b627c:	jmpq   7b59f0 <_Z10acl_reloadP3THD+0x950>
  7b6281:	nopl   0x0(%rax)
  7b6288:	lea    0xd858d3(%rip),%rdi        # 153bb62 <_ZTS14Protocol_local+0x512>
  7b628f:	mov    %rax,%rsi
  7b6292:	mov    $0x5,%ecx
  7b6297:	repz cmpsb %es:(%rdi),%ds:(%rsi)
  7b6299:	seta   %al
  7b629c:	setb   %dl
  7b629f:	sub    %edx,%eax
  7b62a1:	movsbl %al,%eax
  7b62a4:	cmp    $0x1,%eax
  7b62a7:	sbb    %eax,%eax
  7b62a9:	add    $0x3,%eax
  7b62ac:	mov    %eax,-0x8b8(%rbp)
  7b62b2:	jmpq   7b5db3 <_Z10acl_reloadP3THD+0xd13>
  7b62b7:	nopw   0x0(%rax,%rax,1)
  7b62c0:	mov    (%rbx),%rax
  7b62c3:	mov    0x38(%r12),%r13
  7b62c8:	mov    %rbx,%rdi
  7b62cb:	callq  *0x138(%rax)
  7b62d1:	mov    %eax,%eax
  7b62d3:	mov    0x18(%r14),%rdi
  7b62d7:	mov    0x0(%r13,%rax,8),%rsi
  7b62dc:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b62e1:	xor    %edx,%edx
  7b62e3:	test   %rax,%rax
  7b62e6:	je     7b62f6 <_Z10acl_reloadP3THD+0x1256>
  7b62e8:	mov    $0xa,%dl
  7b62ea:	xor    %esi,%esi
  7b62ec:	mov    %rax,%rdi
  7b62ef:	callq  762dc0 <strtol@plt>
  7b62f4:	mov    %eax,%edx
  7b62f6:	mov    %edx,-0x8e4(%rbp)
  7b62fc:	jmpq   7b5f17 <_Z10acl_reloadP3THD+0xe77>
  7b6301:	nopl   0x0(%rax)
  7b6308:	mov    %r13,%rsi
  7b630b:	xor    %edi,%edi
  7b630d:	callq  cb6d60 <_Z13plugin_unlockP3THDP13st_plugin_int>
  7b6312:	mov    (%r12),%rax
  7b6316:	mov    %rbx,%rdi
  7b6319:	mov    0x2b0(%rax),%r13d
  7b6320:	mov    (%rbx),%rax
  7b6323:	callq  *0x150(%rax)
  7b6329:	cmp    %eax,%r13d
  7b632c:	jbe    7b63b8 <_Z10acl_reloadP3THD+0x1318>
  7b6332:	mov    (%rbx),%rax
  7b6335:	mov    0x38(%r12),%r13
  7b633a:	mov    %rbx,%rdi
  7b633d:	callq  *0x150(%rax)
  7b6343:	mov    %eax,%eax
  7b6345:	mov    %r15,%rdi
  7b6348:	mov    0x0(%r13,%rax,8),%rsi
  7b634d:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b6352:	test   %rax,%rax
  7b6355:	je     7b63b8 <_Z10acl_reloadP3THD+0x1318>
  7b6357:	movzbl (%rax),%eax
  7b635a:	and    $0xffffffdf,%eax
  7b635d:	cmp    $0x59,%al
  7b635f:	jne    7b63b8 <_Z10acl_reloadP3THD+0x1318>
  7b6361:	mov    -0x898(%rbp),%rdi
  7b6368:	movb   $0x1,-0x878(%rbp)
  7b636f:	callq  7aa8c0 <_Z31auth_plugin_supports_expirationPKc>
  7b6374:	test   %al,%al
  7b6376:	jne    7b66fc <_Z10acl_reloadP3THD+0x165c>
  7b637c:	mov    -0x920(%rbp),%rdx
  7b6383:	mov    -0x8d8(%rbp),%rcx
  7b638a:	lea    0xd7655f(%rip),%rax        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  7b6391:	lea    0xb69880(%rip),%rdi        # 131fc18 <_ZTS32Find_thd_by_id_with_callback_setItE+0x778>
  7b6398:	test   %rdx,%rdx
  7b639b:	cmove  %rax,%rdx
  7b639f:	test   %rcx,%rcx
  7b63a2:	cmovne %rcx,%rax
  7b63a6:	mov    %rax,%rsi
  7b63a9:	xor    %eax,%eax
  7b63ab:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b63b0:	jmpq   7b5908 <_Z10acl_reloadP3THD+0x868>
  7b63b5:	nopl   (%rax)
  7b63b8:	xor    %r13d,%r13d
  7b63bb:	mov    (%r12),%rax
  7b63bf:	mov    %rbx,%rdi
  7b63c2:	mov    0x2b0(%rax),%eax
  7b63c8:	mov    %eax,-0x2478(%rbp)
  7b63ce:	mov    (%rbx),%rax
  7b63d1:	callq  *0x168(%rax)
  7b63d7:	cmp    %eax,-0x2478(%rbp)
  7b63dd:	ja     7b65d0 <_Z10acl_reloadP3THD+0x1530>
  7b63e3:	movl   $0xffffffff,-0x84c(%rbp)
  7b63ed:	movb   $0x1,-0x844(%rbp)
  7b63f4:	mov    %rbx,%rdi
  7b63f7:	movl   $0x0,-0x848(%rbp)
  7b6401:	mov    (%r12),%rax
  7b6405:	mov    0x2b0(%rax),%eax
  7b640b:	mov    %eax,-0x2478(%rbp)
  7b6411:	mov    (%rbx),%rax
  7b6414:	callq  *0x158(%rax)
  7b641a:	cmp    %eax,-0x2478(%rbp)
  7b6420:	jbe    7b6465 <_Z10acl_reloadP3THD+0x13c5>
  7b6422:	mov    0x38(%r12),%rdx
  7b6427:	mov    (%rbx),%rax
  7b642a:	mov    %rbx,%rdi
  7b642d:	mov    %rdx,-0x2478(%rbp)
  7b6434:	callq  *0x158(%rax)
  7b643a:	mov    -0x2478(%rbp),%rdx
  7b6441:	mov    %eax,%eax
  7b6443:	mov    (%rdx,%rax,8),%rax
  7b6447:	mov    0x10(%rax),%rdx
  7b644b:	test   %rdx,%rdx
  7b644e:	je     7b682e <_Z10acl_reloadP3THD+0x178e>
  7b6454:	movzbl (%rdx),%edx
  7b6457:	test   %dl,0x7e(%rax)
  7b645a:	setne  %al
  7b645d:	test   %al,%al
  7b645f:	je     7b6707 <_Z10acl_reloadP3THD+0x1667>
  7b6465:	mov    (%r12),%rax
  7b6469:	mov    %rbx,%rdi
  7b646c:	mov    0x2b0(%rax),%eax
  7b6472:	mov    %eax,-0x2478(%rbp)
  7b6478:	mov    (%rbx),%rax
  7b647b:	callq  *0x160(%rax)
  7b6481:	cmp    %eax,-0x2478(%rbp)
  7b6487:	jbe    7b5af5 <_Z10acl_reloadP3THD+0xa55>
  7b648d:	mov    0x38(%r12),%rdx
  7b6492:	mov    (%rbx),%rax
  7b6495:	mov    %rbx,%rdi
  7b6498:	mov    %rdx,-0x2478(%rbp)
  7b649f:	callq  *0x160(%rax)
  7b64a5:	mov    -0x2478(%rbp),%rdx
  7b64ac:	mov    %eax,%eax
  7b64ae:	mov    (%rdx,%rax,8),%rax
  7b64b2:	mov    0x10(%rax),%rdx
  7b64b6:	test   %rdx,%rdx
  7b64b9:	je     7b7137 <_Z10acl_reloadP3THD+0x2097>
  7b64bf:	movzbl (%rdx),%edx
  7b64c2:	test   %dl,0x7e(%rax)
  7b64c5:	setne  %al
  7b64c8:	test   %al,%al
  7b64ca:	jne    7b5af5 <_Z10acl_reloadP3THD+0xa55>
  7b64d0:	mov    0x38(%r12),%rdx
  7b64d5:	mov    (%rbx),%rax
  7b64d8:	mov    %rbx,%rdi
  7b64db:	mov    %rdx,-0x2478(%rbp)
  7b64e2:	callq  *0x160(%rax)
  7b64e8:	mov    -0x2478(%rbp),%rdx
  7b64ef:	mov    %eax,%eax
  7b64f1:	mov    %r15,%rdi
  7b64f4:	mov    (%rdx,%rax,8),%rsi
  7b64f8:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b64fd:	xor    %edx,%edx
  7b64ff:	test   %rax,%rax
  7b6502:	je     7b6512 <_Z10acl_reloadP3THD+0x1472>
  7b6504:	mov    $0xa,%dl
  7b6506:	xor    %esi,%esi
  7b6508:	mov    %rax,%rdi
  7b650b:	callq  762dc0 <strtol@plt>
  7b6510:	mov    %eax,%edx
  7b6512:	mov    %edx,-0x848(%rbp)
  7b6518:	movb   $0x0,-0x844(%rbp)
  7b651f:	jmpq   7b5af5 <_Z10acl_reloadP3THD+0xa55>
  7b6524:	nopl   0x0(%rax)
  7b6528:	movl   $0x0,-0x8b8(%rbp)
  7b6532:	jmpq   7b5db3 <_Z10acl_reloadP3THD+0xd13>
  7b6537:	nopw   0x0(%rax,%rax,1)
  7b6540:	mov    -0x2450(%rbp),%rax
  7b6547:	mov    (%rax),%r12
  7b654a:	mov    0x68(%r12),%rdi
  7b654f:	test   %rdi,%rdi
  7b6552:	je     7b6559 <_Z10acl_reloadP3THD+0x14b9>
  7b6554:	callq  ed6140 <pfs_unlock_mutex_v1>
  7b6559:	lea    0x40(%r12),%rdi
  7b655e:	callq  762030 <pthread_mutex_unlock@plt>
  7b6563:	jmpq   7b57eb <_Z10acl_reloadP3THD+0x74b>
  7b6568:	nopl   0x0(%rax,%rax,1)
  7b6570:	mov    -0x2420(%rbp),%rdi
  7b6577:	mov    %eax,-0x2418(%rbp)
  7b657d:	callq  bfeeb0 <_Z15end_read_recordP11READ_RECORD>
  7b6582:	mov    -0x2418(%rbp),%eax
  7b6588:	test   %eax,%eax
  7b658a:	jle    7b6889 <_Z10acl_reloadP3THD+0x17e9>
  7b6590:	mov    -0x2460(%rbp),%rax
  7b6597:	mov    %rbx,%rdi
  7b659a:	mov    %rax,0x398(%r14)
  7b65a1:	mov    (%rbx),%rax
  7b65a4:	callq  *0x178(%rax)
  7b65aa:	jmpq   7b5722 <_Z10acl_reloadP3THD+0x682>
  7b65af:	nop
  7b65b0:	lea    0xb694e9(%rip),%rdi        # 131faa0 <_ZTS32Find_thd_by_id_with_callback_setItE+0x600>
  7b65b7:	xor    %eax,%eax
  7b65b9:	callq  be5b90 <_Z15sql_print_errorPKcz>
  7b65be:	mov    -0x2420(%rbp),%rdi
  7b65c5:	callq  bfeeb0 <_Z15end_read_recordP11READ_RECORD>
  7b65ca:	jmp    7b6590 <_Z10acl_reloadP3THD+0x14f0>
  7b65cc:	nopl   0x0(%rax)
  7b65d0:	mov    0x38(%r12),%rdx
  7b65d5:	mov    (%rbx),%rax
  7b65d8:	mov    %rbx,%rdi
  7b65db:	mov    %rdx,-0x2478(%rbp)
  7b65e2:	callq  *0x168(%rax)
  7b65e8:	mov    -0x2478(%rbp),%rdx
  7b65ef:	mov    %eax,%eax
  7b65f1:	mov    %r15,%rdi
  7b65f4:	mov    (%rdx,%rax,8),%rsi
  7b65f8:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b65fd:	test   %rax,%rax
  7b6600:	je     7b63e3 <_Z10acl_reloadP3THD+0x1343>
  7b6606:	movzbl (%rax),%eax
  7b6609:	and    $0xffffffdf,%eax
  7b660c:	cmp    $0x59,%al
  7b660e:	jne    7b63e3 <_Z10acl_reloadP3THD+0x1343>
  7b6614:	movb   $0x1,-0x843(%rbp)
  7b661b:	jmpq   7b63e3 <_Z10acl_reloadP3THD+0x1343>
  7b6620:	lea    0x1664679(%rip),%rax        # 1e1aca0 <system_charset_info>
  7b6627:	lea    0x15bf652(%rip),%rcx        # 1d75c80 <native_password_plugin_name>
  7b662e:	mov    %r13,%rsi
  7b6631:	mov    (%rax),%rdi
  7b6634:	mov    %rcx,-0x2478(%rbp)
  7b663b:	mov    (%rcx),%rdx
  7b663e:	mov    0xb8(%rdi),%rax
  7b6645:	callq  *0x38(%rax)
  7b6648:	test   %eax,%eax
  7b664a:	je     7b5f75 <_Z10acl_reloadP3THD+0xed5>
  7b6650:	jmpq   7b6040 <_Z10acl_reloadP3THD+0xfa0>
  7b6655:	nopl   (%rax)
  7b6658:	testb  $0x80,-0x8f7(%rbp)
  7b665f:	je     7b667f <_Z10acl_reloadP3THD+0x15df>
  7b6661:	cmpb   $0x0,-0x2458(%rbp)
  7b6668:	jne    7b667f <_Z10acl_reloadP3THD+0x15df>
  7b666a:	test   %r13,%r13
  7b666d:	je     7b746b <_Z10acl_reloadP3THD+0x23cb>
  7b6673:	cmpb   $0x0,0x0(%r13)
  7b6678:	sete   -0x2458(%rbp)
  7b667f:	mov    -0x920(%rbp),%rdx
  7b6686:	mov    -0x8d8(%rbp),%rsi
  7b668d:	lea    0xd7625c(%rip),%rax        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  7b6694:	lea    0xb6944d(%rip),%rdi        # 131fae8 <_ZTS32Find_thd_by_id_with_callback_setItE+0x648>
  7b669b:	mov    %r8,-0x2478(%rbp)
  7b66a2:	test   %rdx,%rdx
  7b66a5:	cmove  %rax,%rdx
  7b66a9:	test   %rsi,%rsi
  7b66ac:	cmove  %rax,%rsi
  7b66b0:	xor    %eax,%eax
  7b66b2:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b66b7:	mov    -0x2478(%rbp),%r8
  7b66be:	xor    %edi,%edi
  7b66c0:	mov    %r8,%rsi
  7b66c3:	callq  cb6d60 <_Z13plugin_unlockP3THDP13st_plugin_int>
  7b66c8:	jmpq   7b5908 <_Z10acl_reloadP3THD+0x868>
  7b66cd:	mov    -0x2480(%rbp),%rax
  7b66d4:	mov    %rax,-0x888(%rbp)
  7b66db:	mov    -0x2488(%rbp),%eax
  7b66e1:	mov    %rax,-0x880(%rbp)
  7b66e8:	jmpq   7b6022 <_Z10acl_reloadP3THD+0xf82>
  7b66ed:	mov    -0x2478(%rbp),%rax
  7b66f4:	mov    (%rax),%r13
  7b66f7:	jmpq   7b6036 <_Z10acl_reloadP3THD+0xf96>
  7b66fc:	mov    $0x1,%r13d
  7b6702:	jmpq   7b63bb <_Z10acl_reloadP3THD+0x131b>
  7b6707:	mov    0x38(%r12),%rdx
  7b670c:	mov    (%rbx),%rax
  7b670f:	mov    %rbx,%rdi
  7b6712:	mov    %rdx,-0x2478(%rbp)
  7b6719:	callq  *0x158(%rax)
  7b671f:	mov    -0x2478(%rbp),%rdx
  7b6726:	mov    %eax,%eax
  7b6728:	mov    %r15,%rdi
  7b672b:	mov    (%rdx,%rax,8),%rsi
  7b672f:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b6734:	test   %rax,%rax
  7b6737:	je     7b6465 <_Z10acl_reloadP3THD+0x13c5>
  7b673d:	lea    0xb69091(%rip),%rsi        # 131f7d5 <_ZTS32Find_thd_by_id_with_callback_setItE+0x335>
  7b6744:	mov    $0x14,%edx
  7b6749:	mov    %rax,%rdi
  7b674c:	mov    %rax,-0x2478(%rbp)
  7b6753:	callq  7632c0 <memcmp@plt>
  7b6758:	test   %eax,%eax
  7b675a:	mov    -0x2478(%rbp),%rcx
  7b6761:	je     7b6465 <_Z10acl_reloadP3THD+0x13c5>
  7b6767:	mov    %rcx,%rdi
  7b676a:	mov    %rcx,-0x2390(%rbp)
  7b6771:	callq  762340 <strlen@plt>
  7b6776:	mov    %rax,-0x2388(%rbp)
  7b677d:	lea    0x15f19bc(%rip),%rax        # 1da8140 <my_charset_bin>
  7b6784:	mov    -0x2498(%rbp),%rdi
  7b678b:	movl   $0x0,-0x2378(%rbp)
  7b6795:	movb   $0x0,-0x2374(%rbp)
  7b679c:	mov    %rax,-0x2380(%rbp)
  7b67a3:	mov    -0x2418(%rbp),%rax
  7b67aa:	lea    0xb0(%rax),%rsi
  7b67b1:	callq  d04010 <_Z21str_to_time_with_warnP6StringP13st_mysql_time>
  7b67b6:	cmpb   $0x0,-0x2374(%rbp)
  7b67bd:	je     7b6465 <_Z10acl_reloadP3THD+0x13c5>
  7b67c3:	mov    -0x2390(%rbp),%rdi
  7b67ca:	movb   $0x0,-0x2374(%rbp)
  7b67d1:	movl   $0x0,-0x2378(%rbp)
  7b67db:	callq  eb6000 <my_free>
  7b67e0:	jmpq   7b6465 <_Z10acl_reloadP3THD+0x13c5>
  7b67e5:	nopl   (%rax)
  7b67e8:	lea    0x16644b1(%rip),%rax        # 1e1aca0 <system_charset_info>
  7b67ef:	lea    0x15bf47a(%rip),%rcx        # 1d75c70 <sha256_password_plugin_name>
  7b67f6:	mov    %r13,%rsi
  7b67f9:	mov    (%rax),%rdi
  7b67fc:	mov    (%rcx),%rdx
  7b67ff:	mov    0xb8(%rdi),%rax
  7b6806:	callq  *0x38(%rax)
  7b6809:	test   %eax,%eax
  7b680b:	jne    7b686e <_Z10acl_reloadP3THD+0x17ce>
  7b680d:	lea    0x15bf45c(%rip),%rax        # 1d75c70 <sha256_password_plugin_name>
  7b6814:	mov    0x8(%rax),%rdx
  7b6818:	mov    (%rax),%rax
  7b681b:	mov    %rdx,-0x890(%rbp)
  7b6822:	mov    %rax,-0x898(%rbp)
  7b6829:	jmpq   7b61d8 <_Z10acl_reloadP3THD+0x1138>
  7b682e:	cmpb   $0x0,0x18(%rax)
  7b6832:	jne    7b7165 <_Z10acl_reloadP3THD+0x20c5>
  7b6838:	mov    0x20(%rax),%rax
  7b683c:	cmpb   $0x0,0x7e9(%rax)
  7b6843:	setne  %al
  7b6846:	jmpq   7b645d <_Z10acl_reloadP3THD+0x13bd>
  7b684b:	lea    0x40(%rbx),%rdi
  7b684f:	callq  7620e0 <pthread_mutex_lock@plt>
  7b6854:	jmpq   7b546e <_Z10acl_reloadP3THD+0x3ce>
  7b6859:	movl   $0x0,-0x2488(%rbp)
  7b6863:	mov    -0x2488(%rbp),%esi
  7b6869:	jmpq   7b5fec <_Z10acl_reloadP3THD+0xf4c>
  7b686e:	mov    %r13,%rdi
  7b6871:	mov    %r13,-0x898(%rbp)
  7b6878:	callq  762340 <strlen@plt>
  7b687d:	mov    %rax,-0x890(%rbp)
  7b6884:	jmpq   7b61d8 <_Z10acl_reloadP3THD+0x1138>
  7b6889:	lea    0x1667870(%rip),%rax        # 1e1e100 <acl_users>
  7b6890:	mov    (%rax),%r12
  7b6893:	mov    (%r12),%rdx
  7b6897:	mov    0x8d0(%r12),%r13
  7b689f:	mov    %rdx,%rax
  7b68a2:	shl    $0x8,%rdx
  7b68a6:	mov    %r13,%r11
  7b68a9:	shl    $0x5,%rax
  7b68ad:	sub    %rax,%rdx
  7b68b0:	lea    0x0(%r13,%rdx,1),%r10
  7b68b5:	cmp    %r10,%r13
  7b68b8:	je     7b6ab3 <_Z10acl_reloadP3THD+0x1a13>
  7b68be:	mov    %r10,%r12
  7b68c1:	movabs $0x6db6db6db6db6db7,%rdx
  7b68cb:	mov    %r10,%rsi
  7b68ce:	sub    %r13,%r12
  7b68d1:	mov    %r13,%rdi
  7b68d4:	mov    %r10,-0x2418(%rbp)
  7b68db:	mov    %r12,%rax
  7b68de:	sar    $0x5,%rax
  7b68e2:	imul   %rdx,%rax
  7b68e6:	bsr    %rax,%rax
  7b68ea:	xor    $0x3f,%rax
  7b68ee:	movslq %eax,%rdx
  7b68f1:	mov    $0x3f,%eax
  7b68f6:	sub    %rdx,%rax
  7b68f9:	lea    (%rax,%rax,1),%rdx
  7b68fd:	callq  7b3f40 <_ZSt16__introsort_loopIP8ACL_USERlN12_GLOBAL__N_111ACL_compareEEvT_S4_T0_T1_.isra.165>
  7b6902:	cmp    $0xedf,%r12
  7b6909:	mov    -0x2418(%rbp),%r10
  7b6910:	jle    7b7367 <_Z10acl_reloadP3THD+0x22c7>
  7b6916:	lea    0xe00(%r13),%r12
  7b691d:	mov    %r13,%rdi
  7b6920:	lea    -0x920(%rbp),%r13
  7b6927:	mov    %r12,%rsi
  7b692a:	callq  7ae500 <_ZSt16__insertion_sortIP8ACL_USERN12_GLOBAL__N_111ACL_compareEEvT_S4_T0_.isra.166>
  7b692f:	mov    -0x2418(%rbp),%r10
  7b6936:	mov    $0x1c,%r9d
  7b693c:	cmp    %r12,%r10
  7b693f:	je     7b6aa1 <_Z10acl_reloadP3THD+0x1a01>
  7b6945:	nopl   (%rax)
  7b6948:	mov    %r13,%rdi
  7b694b:	mov    %r12,%rsi
  7b694e:	mov    %r9,%rcx
  7b6951:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b6954:	lea    -0xe0(%r12),%rdx
  7b695c:	mov    0x20(%r12),%r8
  7b6961:	cmp    -0xc0(%r12),%r8
  7b6969:	jbe    7b6a27 <_Z10acl_reloadP3THD+0x1987>
  7b696f:	mov    %r12,%rcx
  7b6972:	jmp    7b69d0 <_Z10acl_reloadP3THD+0x1930>
  7b6974:	nopl   0x0(%rax)
  7b6978:	test   $0x2,%dil
  7b697c:	jne    7b6a10 <_Z10acl_reloadP3THD+0x1970>
  7b6982:	test   $0x4,%dil
  7b6986:	jne    7b69f8 <_Z10acl_reloadP3THD+0x1958>
  7b6988:	mov    %eax,%ecx
  7b698a:	shr    $0x3,%ecx
  7b698d:	test   $0x4,%al
  7b698f:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b6992:	je     7b699d <_Z10acl_reloadP3THD+0x18fd>
  7b6994:	mov    (%rsi),%ecx
  7b6996:	mov    %ecx,(%rdi)
  7b6998:	mov    $0x4,%ecx
  7b699d:	test   $0x2,%al
  7b699f:	je     7b69af <_Z10acl_reloadP3THD+0x190f>
  7b69a1:	movzwl (%rsi,%rcx,1),%r11d
  7b69a6:	mov    %r11w,(%rdi,%rcx,1)
  7b69ab:	add    $0x2,%rcx
  7b69af:	test   $0x1,%al
  7b69b1:	je     7b69ba <_Z10acl_reloadP3THD+0x191a>
  7b69b3:	movzbl (%rsi,%rcx,1),%eax
  7b69b7:	mov    %al,(%rdi,%rcx,1)
  7b69ba:	cmp    %r8,-0xc0(%rdx)
  7b69c1:	lea    -0xe0(%rdx),%rax
  7b69c8:	jae    7b6a30 <_Z10acl_reloadP3THD+0x1990>
  7b69ca:	mov    %rdx,%rcx
  7b69cd:	mov    %rax,%rdx
  7b69d0:	test   $0x1,%cl
  7b69d3:	mov    %rcx,%rdi
  7b69d6:	mov    %rdx,%rsi
  7b69d9:	mov    $0xde,%eax
  7b69de:	je     7b6978 <_Z10acl_reloadP3THD+0x18d8>
  7b69e0:	movzbl (%rdx),%eax
  7b69e3:	add    $0x1,%rdi
  7b69e7:	lea    0x1(%rdx),%rsi
  7b69eb:	mov    %al,(%rcx)
  7b69ed:	mov    $0xdd,%eax
  7b69f2:	jmp    7b6978 <_Z10acl_reloadP3THD+0x18d8>
  7b69f4:	nopl   0x0(%rax)
  7b69f8:	mov    (%rsi),%ecx
  7b69fa:	add    $0x4,%rdi
  7b69fe:	add    $0x4,%rsi
  7b6a02:	sub    $0x4,%eax
  7b6a05:	mov    %ecx,-0x4(%rdi)
  7b6a08:	jmpq   7b6988 <_Z10acl_reloadP3THD+0x18e8>
  7b6a0d:	nopl   (%rax)
  7b6a10:	movzwl (%rsi),%ecx
  7b6a13:	add    $0x2,%rdi
  7b6a17:	add    $0x2,%rsi
  7b6a1b:	sub    $0x2,%eax
  7b6a1e:	mov    %cx,-0x2(%rdi)
  7b6a22:	jmpq   7b6982 <_Z10acl_reloadP3THD+0x18e2>
  7b6a27:	mov    %r12,%rdx
  7b6a2a:	nopw   0x0(%rax,%rax,1)
  7b6a30:	test   $0x1,%dl
  7b6a33:	mov    %r8,-0x900(%rbp)
  7b6a3a:	mov    %rdx,%rdi
  7b6a3d:	mov    %r13,%rsi
  7b6a40:	mov    $0xde,%eax
  7b6a45:	jne    7b7345 <_Z10acl_reloadP3THD+0x22a5>
  7b6a4b:	test   $0x2,%dil
  7b6a4f:	jne    7b732e <_Z10acl_reloadP3THD+0x228e>
  7b6a55:	test   $0x4,%dil
  7b6a59:	jne    7b7319 <_Z10acl_reloadP3THD+0x2279>
  7b6a5f:	mov    %eax,%ecx
  7b6a61:	xor    %edx,%edx
  7b6a63:	shr    $0x3,%ecx
  7b6a66:	test   $0x4,%al
  7b6a68:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b6a6b:	je     7b6a76 <_Z10acl_reloadP3THD+0x19d6>
  7b6a6d:	mov    (%rsi),%edx
  7b6a6f:	mov    %edx,(%rdi)
  7b6a71:	mov    $0x4,%edx
  7b6a76:	test   $0x2,%al
  7b6a78:	je     7b6a86 <_Z10acl_reloadP3THD+0x19e6>
  7b6a7a:	movzwl (%rsi,%rdx,1),%ecx
  7b6a7e:	mov    %cx,(%rdi,%rdx,1)
  7b6a82:	add    $0x2,%rdx
  7b6a86:	test   $0x1,%al
  7b6a88:	je     7b6a91 <_Z10acl_reloadP3THD+0x19f1>
  7b6a8a:	movzbl (%rsi,%rdx,1),%eax
  7b6a8e:	mov    %al,(%rdi,%rdx,1)
  7b6a91:	add    $0xe0,%r12
  7b6a98:	cmp    %r12,%r10
  7b6a9b:	jne    7b6948 <_Z10acl_reloadP3THD+0x18a8>
  7b6aa1:	lea    0x1667658(%rip),%rax        # 1e1e100 <acl_users>
  7b6aa8:	mov    (%rax),%r12
  7b6aab:	mov    0x8d0(%r12),%r11
  7b6ab3:	lea    0x10(%r12),%rax
  7b6ab8:	cmp    %r11,%rax
  7b6abb:	mov    %rax,-0x2468(%rbp)
  7b6ac2:	je     7b6cbc <_Z10acl_reloadP3THD+0x1c1c>
  7b6ac8:	mov    (%r12),%rax
  7b6acc:	cmp    0x8(%r12),%rax
  7b6ad1:	je     7b6cbc <_Z10acl_reloadP3THD+0x1c1c>
  7b6ad7:	lea    -0x1200(%rbp),%rcx
  7b6ade:	mov    %rax,%rdx
  7b6ae1:	shl    $0x8,%rax
  7b6ae5:	shl    $0x5,%rdx
  7b6ae9:	mov    0x8d8(%r12),%edi
  7b6af1:	movq   $0x0,-0x1200(%rbp)
  7b6afc:	sub    %rdx,%rax
  7b6aff:	lea    0x10(%rcx),%rdx
  7b6b03:	mov    %rcx,-0x2430(%rbp)
  7b6b0a:	lea    (%r11,%rax,1),%r10
  7b6b0e:	sar    $0x5,%rax
  7b6b12:	movq   $0xa,-0x11f8(%rbp)
  7b6b1d:	mov    %rdx,-0x930(%rbp)
  7b6b24:	movabs $0x6db6db6db6db6db7,%rdx
  7b6b2e:	mov    %edi,-0x928(%rbp)
  7b6b34:	imul   %rax,%rdx
  7b6b38:	mov    %rdx,%rcx
  7b6b3b:	mov    %rdx,-0x2418(%rbp)
  7b6b42:	mov    $0xa,%edx
  7b6b47:	cmp    $0xa,%rcx
  7b6b4b:	ja     7b7477 <_Z10acl_reloadP3THD+0x23d7>
  7b6b51:	cmp    %r11,%r10
  7b6b54:	je     7b6c10 <_Z10acl_reloadP3THD+0x1b70>
  7b6b5a:	mov    -0x2430(%rbp),%rax
  7b6b61:	mov    %rbx,-0x2470(%rbp)
  7b6b68:	mov    %r10,%r13
  7b6b6b:	mov    %r11,%rbx
  7b6b6e:	mov    %r12,-0x2478(%rbp)
  7b6b75:	mov    %r14,-0x2480(%rbp)
  7b6b7c:	add    $0x10,%rax
  7b6b80:	mov    %rax,-0x2418(%rbp)
  7b6b87:	jmp    7b6bcf <_Z10acl_reloadP3THD+0x1b2f>
  7b6b89:	nopl   0x0(%rax)
  7b6b90:	lea    0x1(%rax),%rdx
  7b6b94:	mov    %rdx,-0x1200(%rbp)
  7b6b9b:	mov    %rax,%rdx
  7b6b9e:	shl    $0x8,%rax
  7b6ba2:	shl    $0x5,%rdx
  7b6ba6:	sub    %rdx,%rax
  7b6ba9:	add    %r12,%rax
  7b6bac:	je     7b6bbc <_Z10acl_reloadP3THD+0x1b1c>
  7b6bae:	mov    $0x1c,%ecx
  7b6bb3:	mov    %rax,%rdi
  7b6bb6:	mov    %rbx,%rsi
  7b6bb9:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b6bbc:	add    $0xe0,%rbx
  7b6bc3:	cmp    %rbx,%r13
  7b6bc6:	je     7b6bfb <_Z10acl_reloadP3THD+0x1b5b>
  7b6bc8:	mov    -0x11f8(%rbp),%rdx
  7b6bcf:	mov    -0x1200(%rbp),%rax
  7b6bd6:	mov    -0x930(%rbp),%r12
  7b6bdd:	cmp    %rdx,%rax
  7b6be0:	jne    7b6b90 <_Z10acl_reloadP3THD+0x1af0>
  7b6be2:	lea    (%rdx,%rdx,1),%r14
  7b6be6:	cmp    %r14,%rdx
  7b6be9:	jb     7b73c2 <_Z10acl_reloadP3THD+0x2322>
  7b6bef:	mov    -0x930(%rbp),%r12
  7b6bf6:	mov    %rdx,%rax
  7b6bf9:	jmp    7b6b90 <_Z10acl_reloadP3THD+0x1af0>
  7b6bfb:	mov    -0x2470(%rbp),%rbx
  7b6c02:	mov    -0x2478(%rbp),%r12
  7b6c09:	mov    -0x2480(%rbp),%r14
  7b6c10:	mov    -0x2430(%rbp),%rax
  7b6c17:	mov    -0x930(%rbp),%rdx
  7b6c1e:	add    $0x10,%rax
  7b6c22:	cmp    %rax,%rdx
  7b6c25:	je     7b754f <_Z10acl_reloadP3THD+0x24af>
  7b6c2b:	mov    0x8d0(%r12),%rax
  7b6c33:	cmp    %rax,-0x2468(%rbp)
  7b6c3a:	je     7b754f <_Z10acl_reloadP3THD+0x24af>
  7b6c40:	mov    (%r12),%rcx
  7b6c44:	mov    -0x1200(%rbp),%rdx
  7b6c4b:	mov    %rcx,-0x1200(%rbp)
  7b6c52:	mov    %rdx,(%r12)
  7b6c56:	mov    0x8(%r12),%rcx
  7b6c5b:	mov    -0x11f8(%rbp),%rdx
  7b6c62:	mov    %rcx,-0x11f8(%rbp)
  7b6c69:	mov    %rdx,0x8(%r12)
  7b6c6e:	mov    -0x930(%rbp),%rdx
  7b6c75:	mov    %rax,-0x930(%rbp)
  7b6c7c:	mov    %rdx,0x8d0(%r12)
  7b6c84:	mov    0x8d8(%r12),%edx
  7b6c8c:	mov    -0x928(%rbp),%eax
  7b6c92:	mov    %edx,-0x928(%rbp)
  7b6c98:	mov    %eax,0x8d8(%r12)
  7b6ca0:	mov    -0x2430(%rbp),%rax
  7b6ca7:	mov    -0x930(%rbp),%rdi
  7b6cae:	add    $0x10,%rax
  7b6cb2:	cmp    %rax,%rdi
  7b6cb5:	je     7b6cbc <_Z10acl_reloadP3THD+0x1c1c>
  7b6cb7:	callq  eb6000 <my_free>
  7b6cbc:	cmpb   $0x0,-0x2458(%rbp)
  7b6cc3:	jne    7b7377 <_Z10acl_reloadP3THD+0x22d7>
  7b6cc9:	mov    -0x1c40(%rbp),%r12
  7b6cd0:	mov    -0x2420(%rbp),%rdi
  7b6cd7:	xor    %ecx,%ecx
  7b6cd9:	movl   $0x0,(%rsp)
  7b6ce0:	mov    $0x1,%r9d
  7b6ce6:	mov    $0x1,%r8d
  7b6cec:	mov    %r14,%rsi
  7b6cef:	mov    %r12,%rdx
  7b6cf2:	callq  bfe770 <_Z16init_read_recordP11READ_RECORDP3THDP5TABLEP7QEP_TABibb>
  7b6cf7:	test   %al,%al
  7b6cf9:	jne    7b6590 <_Z10acl_reloadP3THD+0x14f0>
  7b6cff:	mov    (%r12),%rax
  7b6d03:	mov    0x8(%r12),%rdi
  7b6d08:	add    $0x1c0,%rax
  7b6d0e:	test   %rdi,%rdi
  7b6d11:	mov    %rax,0x1a8(%r12)
  7b6d19:	mov    %rax,0x1b0(%r12)
  7b6d21:	je     7b6d32 <_Z10acl_reloadP3THD+0x1c92>
  7b6d23:	cmpb   $0x0,0x7ff(%r12)
  7b6d2c:	jne    7b7a7f <_Z10acl_reloadP3THD+0x29df>
  7b6d32:	lea    0x16673a7(%rip),%rax        # 1e1e0e0 <acl_dbs>
  7b6d39:	lea    -0x2390(%rbp),%r13
  7b6d40:	mov    (%rax),%rax
  7b6d43:	movq   $0x0,(%rax)
  7b6d4a:	lea    -0x920(%rbp),%rax
  7b6d51:	mov    %rax,-0x2418(%rbp)
  7b6d58:	nopl   0x0(%rax,%rax,1)
  7b6d60:	mov    -0x2420(%rbp),%rdi
  7b6d67:	callq  *-0x2308(%rbp)
  7b6d6d:	test   %eax,%eax
  7b6d6f:	jne    7b716e <_Z10acl_reloadP3THD+0x20ce>
  7b6d75:	mov    0x38(%r12),%rax
  7b6d7a:	mov    %r15,%rdi
  7b6d7d:	mov    (%rax),%rsi
  7b6d80:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b6d85:	mov    %r13,%rdi
  7b6d88:	mov    %rax,%rsi
  7b6d8b:	callq  7af0d0 <_ZN15ACL_HOST_AND_IP15update_hostnameEPKc>
  7b6d90:	mov    0x38(%r12),%rax
  7b6d95:	mov    %r15,%rdi
  7b6d98:	mov    0x8(%rax),%rsi
  7b6d9c:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b6da1:	test   %rax,%rax
  7b6da4:	mov    %rax,-0x2358(%rbp)
  7b6dab:	je     7b7154 <_Z10acl_reloadP3THD+0x20b4>
  7b6db1:	mov    0x38(%r12),%rax
  7b6db6:	mov    %r15,%rdi
  7b6db9:	mov    0x10(%rax),%rsi
  7b6dbd:	callq  d2e470 <_Z9get_fieldP11st_mem_rootP5Field>
  7b6dc2:	cmpb   $0x0,-0x2424(%rbp)
  7b6dc9:	mov    %rax,-0x2360(%rbp)
  7b6dd0:	jne    7b6fcd <_Z10acl_reloadP3THD+0x1f2d>
  7b6dd6:	xor    %edx,%edx
  7b6dd8:	mov    $0x3,%esi
  7b6ddd:	mov    %r12,%rdi
  7b6de0:	callq  7bafc0 <_Z10get_accessP5TABLEjPj>
  7b6de5:	mov    %rax,%rdx
  7b6de8:	mov    %rax,%rcx
  7b6deb:	mov    %rax,%rsi
  7b6dee:	shl    $0x4,%rdx
  7b6df2:	shl    $0x6,%rcx
  7b6df6:	shl    $0x9,%rsi
  7b6dfa:	and    $0x30000,%ecx
  7b6e00:	and    $0x3c00,%edx
  7b6e06:	or     %rcx,%rdx
  7b6e09:	mov    %rax,%rcx
  7b6e0c:	shl    $0x2,%rax
  7b6e10:	and    $0x3f,%ecx
  7b6e13:	and    $0x40000,%eax
  7b6e18:	or     %rcx,%rdx
  7b6e1b:	mov    %rsi,%rcx
  7b6e1e:	and    $0xc000000,%esi
  7b6e24:	and    $0x1e00000,%ecx
  7b6e2a:	or     %rcx,%rdx
  7b6e2d:	or     %rax,%rdx
  7b6e30:	lea    0x1666669(%rip),%rax        # 1e1d4a0 <lower_case_table_names>
  7b6e37:	or     %rsi,%rdx
  7b6e3a:	mov    %rdx,-0x2368(%rbp)
  7b6e41:	mov    (%rax),%eax
  7b6e43:	test   %eax,%eax
  7b6e45:	jne    7b6f26 <_Z10acl_reloadP3THD+0x1e86>
  7b6e4b:	mov    -0x2358(%rbp),%r8
  7b6e52:	mov    -0x2360(%rbp),%rcx
  7b6e59:	mov    -0x2390(%rbp),%rsi
  7b6e60:	xor    %eax,%eax
  7b6e62:	mov    %r8,%rdx
  7b6e65:	mov    $0x3,%edi
  7b6e6a:	callq  7af9f0 <_Z8get_sortjz>
  7b6e6f:	mov    %rax,-0x2370(%rbp)
  7b6e76:	mov    (%r12),%rax
  7b6e7a:	cmpl   $0x9,0x2b0(%rax)
  7b6e81:	ja     7b6e98 <_Z10acl_reloadP3THD+0x1df8>
  7b6e83:	mov    -0x2368(%rbp),%rax
  7b6e8a:	test   $0x10,%al
  7b6e8c:	je     7b6e98 <_Z10acl_reloadP3THD+0x1df8>
  7b6e8e:	or     $0x38,%ah
  7b6e91:	mov    %rax,-0x2368(%rbp)
  7b6e98:	lea    0x1667241(%rip),%rax        # 1e1e0e0 <acl_dbs>
  7b6e9f:	mov    (%rax),%rcx
  7b6ea2:	mov    (%rcx),%r8
  7b6ea5:	cmp    0x8(%rcx),%r8
  7b6ea9:	je     7b7025 <_Z10acl_reloadP3THD+0x1f85>
  7b6eaf:	mov    0x290(%rcx),%rax
  7b6eb6:	lea    0x1(%r8),%rdx
  7b6eba:	shl    $0x6,%r8
  7b6ebe:	add    %r8,%rax
  7b6ec1:	mov    %rdx,(%rcx)
  7b6ec4:	je     7b6d60 <_Z10acl_reloadP3THD+0x1cc0>
  7b6eca:	mov    -0x2390(%rbp),%rdx
  7b6ed1:	mov    %rdx,(%rax)
  7b6ed4:	mov    -0x2388(%rbp),%rdx
  7b6edb:	mov    %rdx,0x8(%rax)
  7b6edf:	mov    -0x2380(%rbp),%rdx
  7b6ee6:	mov    %rdx,0x10(%rax)
  7b6eea:	mov    -0x2378(%rbp),%rdx
  7b6ef1:	mov    %rdx,0x18(%rax)
  7b6ef5:	mov    -0x2370(%rbp),%rdx
  7b6efc:	mov    %rdx,0x20(%rax)
  7b6f00:	mov    -0x2368(%rbp),%rdx
  7b6f07:	mov    %rdx,0x28(%rax)
  7b6f0b:	mov    -0x2360(%rbp),%rdx
  7b6f12:	mov    %rdx,0x30(%rax)
  7b6f16:	mov    -0x2358(%rbp),%rdx
  7b6f1d:	mov    %rdx,0x38(%rax)
  7b6f21:	jmpq   7b6d60 <_Z10acl_reloadP3THD+0x1cc0>
  7b6f26:	mov    -0x2358(%rbp),%rdx
  7b6f2d:	mov    -0x2418(%rbp),%rdi
  7b6f34:	mov    %rdx,%rsi
  7b6f37:	mov    %rdx,-0x2430(%rbp)
  7b6f3e:	callq  762350 <strcpy@plt>
  7b6f43:	lea    0x1663d46(%rip),%rax        # 1e1ac90 <files_charset_info>
  7b6f4a:	mov    -0x2430(%rbp),%rdx
  7b6f51:	mov    (%rax),%rdi
  7b6f54:	mov    %rdx,%rsi
  7b6f57:	mov    0xb0(%rdi),%rax
  7b6f5e:	callq  *0x60(%rax)
  7b6f61:	mov    -0x2358(%rbp),%r8
  7b6f68:	mov    -0x2418(%rbp),%rsi
  7b6f6f:	mov    %r8,%rdi
  7b6f72:	mov    %r8,-0x2430(%rbp)
  7b6f79:	callq  762cc0 <strcmp@plt>
  7b6f7e:	test   %eax,%eax
  7b6f80:	mov    -0x2430(%rbp),%r8
  7b6f87:	je     7b6e52 <_Z10acl_reloadP3THD+0x1db2>
  7b6f8d:	mov    -0x2390(%rbp),%rax
  7b6f94:	lea    0xd75955(%rip),%rcx        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  7b6f9b:	lea    0xd7594e(%rip),%rdx        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  7b6fa2:	lea    0xb68fd7(%rip),%rdi        # 131ff80 <_ZTS32Find_thd_by_id_with_callback_setItE+0xae0>
  7b6fa9:	mov    %r8,%rsi
  7b6fac:	test   %rax,%rax
  7b6faf:	cmovne %rax,%rcx
  7b6fb3:	mov    -0x2360(%rbp),%rax
  7b6fba:	test   %rax,%rax
  7b6fbd:	cmovne %rax,%rdx
  7b6fc1:	xor    %eax,%eax
  7b6fc3:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b6fc8:	jmpq   7b6e4b <_Z10acl_reloadP3THD+0x1dab>
  7b6fcd:	mov    -0x2390(%rbp),%rdi
  7b6fd4:	callq  7afdc0 <_Z27hostname_requires_resolvingPKc>
  7b6fd9:	test   %al,%al
  7b6fdb:	je     7b6dd6 <_Z10acl_reloadP3THD+0x1d36>
  7b6fe1:	mov    -0x2390(%rbp),%rax
  7b6fe8:	lea    0xd75901(%rip),%rcx        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  7b6fef:	lea    0xd758fa(%rip),%rdx        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  7b6ff6:	mov    -0x2358(%rbp),%rsi
  7b6ffd:	lea    0xb68f3c(%rip),%rdi        # 131ff40 <_ZTS32Find_thd_by_id_with_callback_setItE+0xaa0>
  7b7004:	test   %rax,%rax
  7b7007:	cmovne %rax,%rcx
  7b700b:	mov    -0x2360(%rbp),%rax
  7b7012:	test   %rax,%rax
  7b7015:	cmovne %rax,%rdx
  7b7019:	xor    %eax,%eax
  7b701b:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b7020:	jmpq   7b6dd6 <_Z10acl_reloadP3THD+0x1d36>
  7b7025:	lea    (%r8,%r8,1),%r9
  7b7029:	cmp    %r9,%r8
  7b702c:	jae    7b6eaf <_Z10acl_reloadP3THD+0x1e0f>
  7b7032:	mov    0x298(%rcx),%edi
  7b7038:	mov    %r8,%rsi
  7b703b:	mov    $0x10,%edx
  7b7040:	shl    $0x7,%rsi
  7b7044:	mov    %r9,-0x2458(%rbp)
  7b704b:	mov    %rcx,-0x2430(%rbp)
  7b7052:	callq  eb5ec0 <my_malloc>
  7b7057:	test   %rax,%rax
  7b705a:	je     7b6d60 <_Z10acl_reloadP3THD+0x1cc0>
  7b7060:	mov    -0x2430(%rbp),%rcx
  7b7067:	xor    %r10d,%r10d
  7b706a:	mov    %rax,%rdx
  7b706d:	mov    -0x2458(%rbp),%r9
  7b7074:	mov    (%rcx),%r8
  7b7077:	mov    0x290(%rcx),%rdi
  7b707e:	test   %r8,%r8
  7b7081:	je     7b70ec <_Z10acl_reloadP3THD+0x204c>
  7b7083:	nopl   0x0(%rax,%rax,1)
  7b7088:	mov    %r10,%rsi
  7b708b:	shl    $0x6,%rsi
  7b708f:	add    %rdi,%rsi
  7b7092:	test   %rdx,%rdx
  7b7095:	je     7b70df <_Z10acl_reloadP3THD+0x203f>
  7b7097:	mov    (%rsi),%rdi
  7b709a:	mov    %rdi,(%rdx)
  7b709d:	mov    0x8(%rsi),%rdi
  7b70a1:	mov    %rdi,0x8(%rdx)
  7b70a5:	mov    0x10(%rsi),%rdi
  7b70a9:	mov    %rdi,0x10(%rdx)
  7b70ad:	mov    0x18(%rsi),%rdi
  7b70b1:	mov    %rdi,0x18(%rdx)
  7b70b5:	mov    0x20(%rsi),%rdi
  7b70b9:	mov    %rdi,0x20(%rdx)
  7b70bd:	mov    0x28(%rsi),%rdi
  7b70c1:	mov    %rdi,0x28(%rdx)
  7b70c5:	mov    0x30(%rsi),%rdi
  7b70c9:	mov    %rdi,0x30(%rdx)
  7b70cd:	mov    0x38(%rsi),%rsi
  7b70d1:	mov    %rsi,0x38(%rdx)
  7b70d5:	mov    0x290(%rcx),%rdi
  7b70dc:	mov    (%rcx),%r8
  7b70df:	add    $0x1,%r10
  7b70e3:	add    $0x40,%rdx
  7b70e7:	cmp    %r8,%r10
  7b70ea:	jb     7b7088 <_Z10acl_reloadP3THD+0x1fe8>
  7b70ec:	lea    0x10(%rcx),%rdx
  7b70f0:	cmp    %rdx,%rdi
  7b70f3:	je     7b7127 <_Z10acl_reloadP3THD+0x2087>
  7b70f5:	mov    %rax,-0x2468(%rbp)
  7b70fc:	mov    %r9,-0x2458(%rbp)
  7b7103:	mov    %rcx,-0x2430(%rbp)
  7b710a:	callq  eb6000 <my_free>
  7b710f:	mov    -0x2430(%rbp),%rcx
  7b7116:	mov    -0x2468(%rbp),%rax
  7b711d:	mov    -0x2458(%rbp),%r9
  7b7124:	mov    (%rcx),%r8
  7b7127:	mov    %rax,0x290(%rcx)
  7b712e:	mov    %r9,0x8(%rcx)
  7b7132:	jmpq   7b6eb6 <_Z10acl_reloadP3THD+0x1e16>
  7b7137:	cmpb   $0x0,0x18(%rax)
  7b713b:	jne    7b735e <_Z10acl_reloadP3THD+0x22be>
  7b7141:	mov    0x20(%rax),%rax
  7b7145:	cmpb   $0x0,0x7e9(%rax)
  7b714c:	setne  %al
  7b714f:	jmpq   7b64c8 <_Z10acl_reloadP3THD+0x1428>
  7b7154:	lea    0xb68d9d(%rip),%rdi        # 131fef8 <_ZTS32Find_thd_by_id_with_callback_setItE+0xa58>
  7b715b:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b7160:	jmpq   7b6d60 <_Z10acl_reloadP3THD+0x1cc0>
  7b7165:	movzbl 0x19(%rax),%eax
  7b7169:	jmpq   7b645d <_Z10acl_reloadP3THD+0x13bd>
  7b716e:	mov    -0x2420(%rbp),%rdi
  7b7175:	mov    %eax,-0x2418(%rbp)
  7b717b:	callq  bfeeb0 <_Z15end_read_recordP11READ_RECORD>
  7b7180:	mov    -0x2418(%rbp),%eax
  7b7186:	test   %eax,%eax
  7b7188:	jg     7b6590 <_Z10acl_reloadP3THD+0x14f0>
  7b718e:	lea    0x1666f4b(%rip),%rax        # 1e1e0e0 <acl_dbs>
  7b7195:	mov    (%rax),%rax
  7b7198:	mov    0x290(%rax),%r13
  7b719f:	mov    (%rax),%rax
  7b71a2:	shl    $0x6,%rax
  7b71a6:	add    %r13,%rax
  7b71a9:	cmp    %rax,%r13
  7b71ac:	mov    %rax,-0x2418(%rbp)
  7b71b3:	je     7b7ac7 <_Z10acl_reloadP3THD+0x2a27>
  7b71b9:	mov    %rax,%r12
  7b71bc:	mov    %rax,%rsi
  7b71bf:	mov    %r13,%rdi
  7b71c2:	sub    %r13,%r12
  7b71c5:	mov    %r12,%rax
  7b71c8:	sar    $0x6,%rax
  7b71cc:	bsr    %rax,%rax
  7b71d0:	xor    $0x3f,%rax
  7b71d4:	movslq %eax,%rdx
  7b71d7:	mov    $0x3f,%eax
  7b71dc:	sub    %rdx,%rax
  7b71df:	lea    (%rax,%rax,1),%rdx
  7b71e3:	callq  7aea10 <_ZSt16__introsort_loopIP6ACL_DBlN12_GLOBAL__N_111ACL_compareEEvT_S4_T0_T1_.isra.172>
  7b71e8:	cmp    $0x43f,%r12
  7b71ef:	jle    7b7d5e <_Z10acl_reloadP3THD+0x2cbe>
  7b71f5:	lea    0x400(%r13),%r12
  7b71fc:	lea    0x40(%r13),%rax
  7b7200:	jmpq   7b72ef <_Z10acl_reloadP3THD+0x224f>
  7b7205:	mov    0x18(%rax),%rcx
  7b7209:	mov    (%rax),%r11
  7b720c:	mov    0x8(%rax),%r10
  7b7210:	mov    0x10(%rax),%r9
  7b7214:	mov    %rcx,-0x2430(%rbp)
  7b721b:	mov    0x28(%rax),%rcx
  7b721f:	mov    %rcx,-0x2458(%rbp)
  7b7226:	mov    0x30(%rax),%rcx
  7b722a:	mov    %rcx,-0x2468(%rbp)
  7b7231:	mov    0x38(%rax),%rcx
  7b7235:	mov    %rcx,-0x2470(%rbp)
  7b723c:	lea    0x40(%rax),%rcx
  7b7240:	sub    %r13,%rax
  7b7243:	sar    $0x6,%rax
  7b7247:	test   %rax,%rax
  7b724a:	je     7b72a7 <_Z10acl_reloadP3THD+0x2207>
  7b724c:	mov    %rax,%rdx
  7b724f:	mov    %rcx,%rdi
  7b7252:	mov    %r13,%rsi
  7b7255:	shl    $0x6,%rdx
  7b7259:	mov    %r9,-0x2498(%rbp)
  7b7260:	mov    %r10,-0x2490(%rbp)
  7b7267:	sub    %rdx,%rdi
  7b726a:	mov    %r11,-0x2488(%rbp)
  7b7271:	mov    %r8,-0x2480(%rbp)
  7b7278:	mov    %rcx,-0x2478(%rbp)
  7b727f:	callq  761ec0 <memmove@plt>
  7b7284:	mov    -0x2498(%rbp),%r9
  7b728b:	mov    -0x2490(%rbp),%r10
  7b7292:	mov    -0x2488(%rbp),%r11
  7b7299:	mov    -0x2480(%rbp),%r8
  7b72a0:	mov    -0x2478(%rbp),%rcx
  7b72a7:	mov    -0x2430(%rbp),%rax
  7b72ae:	mov    %r11,0x0(%r13)
  7b72b2:	mov    %r10,0x8(%r13)
  7b72b6:	mov    %r9,0x10(%r13)
  7b72ba:	mov    %r8,0x20(%r13)
  7b72be:	mov    %rax,0x18(%r13)
  7b72c2:	mov    -0x2458(%rbp),%rax
  7b72c9:	mov    %rax,0x28(%r13)
  7b72cd:	mov    -0x2468(%rbp),%rax
  7b72d4:	mov    %rax,0x30(%r13)
  7b72d8:	mov    -0x2470(%rbp),%rax
  7b72df:	mov    %rax,0x38(%r13)
  7b72e3:	cmp    %r12,%rcx
  7b72e6:	mov    %rcx,%rax
  7b72e9:	je     7b7f78 <_Z10acl_reloadP3THD+0x2ed8>
  7b72ef:	mov    0x20(%rax),%r8
  7b72f3:	cmp    0x20(%r13),%r8
  7b72f7:	ja     7b7205 <_Z10acl_reloadP3THD+0x2165>
  7b72fd:	mov    %rax,%rdi
  7b7300:	mov    %rax,-0x2430(%rbp)
  7b7307:	callq  763669 <_ZSt25__unguarded_linear_insertIP6ACL_DBN12_GLOBAL__N_111ACL_compareEEvT_T0_.isra.22>
  7b730c:	mov    -0x2430(%rbp),%rax
  7b7313:	lea    0x40(%rax),%rcx
  7b7317:	jmp    7b72e3 <_Z10acl_reloadP3THD+0x2243>
  7b7319:	mov    (%rsi),%edx
  7b731b:	add    $0x4,%rdi
  7b731f:	add    $0x4,%rsi
  7b7323:	sub    $0x4,%eax
  7b7326:	mov    %edx,-0x4(%rdi)
  7b7329:	jmpq   7b6a5f <_Z10acl_reloadP3THD+0x19bf>
  7b732e:	movzwl (%rsi),%edx
  7b7331:	add    $0x2,%rdi
  7b7335:	add    $0x2,%rsi
  7b7339:	sub    $0x2,%eax
  7b733c:	mov    %dx,-0x2(%rdi)
  7b7340:	jmpq   7b6a55 <_Z10acl_reloadP3THD+0x19b5>
  7b7345:	movzbl 0x0(%r13),%eax
  7b734a:	add    $0x1,%rdi
  7b734e:	lea    0x1(%r13),%rsi
  7b7352:	mov    %al,(%rdx)
  7b7354:	mov    $0xdd,%eax
  7b7359:	jmpq   7b6a4b <_Z10acl_reloadP3THD+0x19ab>
  7b735e:	movzbl 0x19(%rax),%eax
  7b7362:	jmpq   7b64c8 <_Z10acl_reloadP3THD+0x1428>
  7b7367:	mov    %r10,%rsi
  7b736a:	mov    %r13,%rdi
  7b736d:	callq  7ae500 <_ZSt16__insertion_sortIP8ACL_USERN12_GLOBAL__N_111ACL_compareEEvT_S4_T0_.isra.166>
  7b7372:	jmpq   7b6aa1 <_Z10acl_reloadP3THD+0x1a01>
  7b7377:	lea    0xb6893a(%rip),%rdi        # 131fcb8 <_ZTS32Find_thd_by_id_with_callback_setItE+0x818>
  7b737e:	xor    %eax,%eax
  7b7380:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b7385:	lea    0xb68a64(%rip),%rdi        # 131fdf0 <_ZTS32Find_thd_by_id_with_callback_setItE+0x950>
  7b738c:	xor    %eax,%eax
  7b738e:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b7393:	lea    0xb6844f(%rip),%rdi        # 131f7e9 <_ZTS32Find_thd_by_id_with_callback_setItE+0x349>
  7b739a:	xor    %eax,%eax
  7b739c:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b73a1:	lea    0xb68a88(%rip),%rdi        # 131fe30 <_ZTS32Find_thd_by_id_with_callback_setItE+0x990>
  7b73a8:	xor    %eax,%eax
  7b73aa:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b73af:	lea    0xb68aba(%rip),%rdi        # 131fe70 <_ZTS32Find_thd_by_id_with_callback_setItE+0x9d0>
  7b73b6:	xor    %eax,%eax
  7b73b8:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b73bd:	jmpq   7b6cc9 <_Z10acl_reloadP3THD+0x1c29>
  7b73c2:	mov    %rdx,%rax
  7b73c5:	mov    %rdx,%rsi
  7b73c8:	mov    -0x928(%rbp),%edi
  7b73ce:	shl    $0x6,%rax
  7b73d2:	shl    $0x9,%rsi
  7b73d6:	mov    $0x10,%edx
  7b73db:	sub    %rax,%rsi
  7b73de:	callq  eb5ec0 <my_malloc>
  7b73e3:	test   %rax,%rax
  7b73e6:	mov    %rax,%r12
  7b73e9:	je     7b6bbc <_Z10acl_reloadP3THD+0x1b1c>
  7b73ef:	mov    -0x1200(%rbp),%rax
  7b73f6:	xor    %r8d,%r8d
  7b73f9:	mov    -0x930(%rbp),%rdi
  7b7400:	mov    %r12,%rdx
  7b7403:	mov    $0x1c,%r9d
  7b7409:	test   %rax,%rax
  7b740c:	je     7b7443 <_Z10acl_reloadP3THD+0x23a3>
  7b740e:	mov    %rdx,%rsi
  7b7411:	sub    %r12,%rsi
  7b7414:	add    %rdi,%rsi
  7b7417:	test   %rdx,%rdx
  7b741a:	je     7b7433 <_Z10acl_reloadP3THD+0x2393>
  7b741c:	mov    %rdx,%rdi
  7b741f:	mov    %r9,%rcx
  7b7422:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b7425:	mov    -0x930(%rbp),%rdi
  7b742c:	mov    -0x1200(%rbp),%rax
  7b7433:	add    $0x1,%r8
  7b7437:	add    $0xe0,%rdx
  7b743e:	cmp    %rax,%r8
  7b7441:	jb     7b740e <_Z10acl_reloadP3THD+0x236e>
  7b7443:	cmp    -0x2418(%rbp),%rdi
  7b744a:	je     7b7458 <_Z10acl_reloadP3THD+0x23b8>
  7b744c:	callq  eb6000 <my_free>
  7b7451:	mov    -0x1200(%rbp),%rax
  7b7458:	mov    %r12,-0x930(%rbp)
  7b745f:	mov    %r14,-0x11f8(%rbp)
  7b7466:	jmpq   7b6b90 <_Z10acl_reloadP3THD+0x1af0>
  7b746b:	movb   $0x1,-0x2458(%rbp)
  7b7472:	jmpq   7b667f <_Z10acl_reloadP3THD+0x15df>
  7b7477:	shl    $0x5,%rax
  7b747b:	mov    $0x10,%dl
  7b747d:	mov    %r11,-0x2478(%rbp)
  7b7484:	mov    %rax,%rsi
  7b7487:	mov    %r10,-0x2470(%rbp)
  7b748e:	callq  eb5ec0 <my_malloc>
  7b7493:	test   %rax,%rax
  7b7496:	mov    %rax,%r13
  7b7499:	mov    -0x2470(%rbp),%r10
  7b74a0:	mov    -0x2478(%rbp),%r11
  7b74a7:	je     7b6c10 <_Z10acl_reloadP3THD+0x1b70>
  7b74ad:	mov    -0x1200(%rbp),%rax
  7b74b4:	xor    %r8d,%r8d
  7b74b7:	mov    -0x930(%rbp),%rdi
  7b74be:	mov    %r13,%rdx
  7b74c1:	mov    $0x1c,%r9d
  7b74c7:	test   %rax,%rax
  7b74ca:	je     7b7501 <_Z10acl_reloadP3THD+0x2461>
  7b74cc:	mov    %rdx,%rsi
  7b74cf:	sub    %r13,%rsi
  7b74d2:	add    %rdi,%rsi
  7b74d5:	test   %rdx,%rdx
  7b74d8:	je     7b74f1 <_Z10acl_reloadP3THD+0x2451>
  7b74da:	mov    %rdx,%rdi
  7b74dd:	mov    %r9,%rcx
  7b74e0:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b74e3:	mov    -0x930(%rbp),%rdi
  7b74ea:	mov    -0x1200(%rbp),%rax
  7b74f1:	add    $0x1,%r8
  7b74f5:	add    $0xe0,%rdx
  7b74fc:	cmp    %rax,%r8
  7b74ff:	jb     7b74cc <_Z10acl_reloadP3THD+0x242c>
  7b7501:	mov    -0x2430(%rbp),%rax
  7b7508:	add    $0x10,%rax
  7b750c:	cmp    %rax,%rdi
  7b750f:	je     7b7532 <_Z10acl_reloadP3THD+0x2492>
  7b7511:	mov    %r11,-0x2478(%rbp)
  7b7518:	mov    %r10,-0x2470(%rbp)
  7b751f:	callq  eb6000 <my_free>
  7b7524:	mov    -0x2478(%rbp),%r11
  7b752b:	mov    -0x2470(%rbp),%r10
  7b7532:	mov    -0x2418(%rbp),%rax
  7b7539:	mov    %r13,-0x930(%rbp)
  7b7540:	mov    %rax,-0x11f8(%rbp)
  7b7547:	mov    %rax,%rdx
  7b754a:	jmpq   7b6b51 <_Z10acl_reloadP3THD+0x1ab1>
  7b754f:	lea    -0x920(%rbp),%r13
  7b7556:	mov    -0x11f8(%rbp),%rsi
  7b755d:	movq   $0x0,-0x920(%rbp)
  7b7568:	movq   $0xa,-0x918(%rbp)
  7b7573:	mov    %rdx,-0x2418(%rbp)
  7b757a:	lea    0x10(%r13),%rax
  7b757e:	cmp    $0xa,%rsi
  7b7582:	mov    %rax,-0x50(%rbp)
  7b7586:	mov    -0x928(%rbp),%eax
  7b758c:	mov    %eax,-0x48(%rbp)
  7b758f:	ja     7b7c7f <_Z10acl_reloadP3THD+0x2bdf>
  7b7595:	mov    -0x1200(%rbp),%rax
  7b759c:	mov    %rax,%rdx
  7b759f:	shl    $0x8,%rax
  7b75a3:	shl    $0x5,%rdx
  7b75a7:	cmp    %rdx,%rax
  7b75aa:	je     7b7703 <_Z10acl_reloadP3THD+0x2663>
  7b75b0:	lea    0x10(%r13),%rax
  7b75b4:	mov    %rax,-0x2480(%rbp)
  7b75bb:	jmp    7b7625 <_Z10acl_reloadP3THD+0x2585>
  7b75bd:	mov    -0x50(%rbp),%rcx
  7b75c1:	lea    0x1(%rax),%rdx
  7b75c5:	mov    %rdx,-0x920(%rbp)
  7b75cc:	mov    %rax,%rdx
  7b75cf:	shl    $0x8,%rax
  7b75d3:	shl    $0x5,%rdx
  7b75d7:	sub    %rdx,%rax
  7b75da:	add    %rcx,%rax
  7b75dd:	je     7b75f1 <_Z10acl_reloadP3THD+0x2551>
  7b75df:	mov    $0x1c,%ecx
  7b75e4:	mov    %rax,%rdi
  7b75e7:	mov    -0x2418(%rbp),%rsi
  7b75ee:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b75f1:	mov    -0x1200(%rbp),%rax
  7b75f8:	addq   $0xe0,-0x2418(%rbp)
  7b7603:	mov    %rax,%rdx
  7b7606:	shl    $0x8,%rax
  7b760a:	shl    $0x5,%rdx
  7b760e:	sub    %rdx,%rax
  7b7611:	add    -0x930(%rbp),%rax
  7b7618:	cmp    %rax,-0x2418(%rbp)
  7b761f:	je     7b7703 <_Z10acl_reloadP3THD+0x2663>
  7b7625:	mov    -0x920(%rbp),%rax
  7b762c:	cmp    -0x918(%rbp),%rax
  7b7633:	jne    7b75bd <_Z10acl_reloadP3THD+0x251d>
  7b7635:	lea    (%rax,%rax,1),%rcx
  7b7639:	cmp    %rcx,%rax
  7b763c:	mov    %rcx,-0x2478(%rbp)
  7b7643:	jae    7b75bd <_Z10acl_reloadP3THD+0x251d>
  7b7649:	mov    %rax,%rdx
  7b764c:	mov    -0x48(%rbp),%edi
  7b764f:	shl    $0x9,%rax
  7b7653:	shl    $0x6,%rdx
  7b7657:	mov    %rax,%rsi
  7b765a:	sub    %rdx,%rsi
  7b765d:	mov    $0x10,%edx
  7b7662:	callq  eb5ec0 <my_malloc>
  7b7667:	test   %rax,%rax
  7b766a:	mov    %rax,-0x2470(%rbp)
  7b7671:	je     7b75f1 <_Z10acl_reloadP3THD+0x2551>
  7b7677:	mov    -0x920(%rbp),%rcx
  7b767e:	mov    -0x50(%rbp),%rdi
  7b7682:	test   %rcx,%rcx
  7b7685:	je     7b76ca <_Z10acl_reloadP3THD+0x262a>
  7b7687:	mov    -0x2470(%rbp),%r9
  7b768e:	xor    %r8d,%r8d
  7b7691:	mov    $0x1c,%edx
  7b7696:	mov    %r9,%rax
  7b7699:	mov    %rax,%rsi
  7b769c:	sub    %r9,%rsi
  7b769f:	add    %rdi,%rsi
  7b76a2:	test   %rax,%rax
  7b76a5:	je     7b76bb <_Z10acl_reloadP3THD+0x261b>
  7b76a7:	mov    %rax,%rdi
  7b76aa:	mov    %rdx,%rcx
  7b76ad:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b76b0:	mov    -0x50(%rbp),%rdi
  7b76b4:	mov    -0x920(%rbp),%rcx
  7b76bb:	add    $0x1,%r8
  7b76bf:	add    $0xe0,%rax
  7b76c5:	cmp    %rcx,%r8
  7b76c8:	jb     7b7699 <_Z10acl_reloadP3THD+0x25f9>
  7b76ca:	cmp    -0x2480(%rbp),%rdi
  7b76d1:	je     7b76df <_Z10acl_reloadP3THD+0x263f>
  7b76d3:	callq  eb6000 <my_free>
  7b76d8:	mov    -0x920(%rbp),%rcx
  7b76df:	mov    -0x2470(%rbp),%rsi
  7b76e6:	mov    -0x2478(%rbp),%rax
  7b76ed:	mov    %rsi,-0x50(%rbp)
  7b76f1:	mov    %rax,-0x918(%rbp)
  7b76f8:	mov    %rcx,%rax
  7b76fb:	mov    %rsi,%rcx
  7b76fe:	jmpq   7b75c1 <_Z10acl_reloadP3THD+0x2521>
  7b7703:	mov    0x8(%r12),%rsi
  7b7708:	cmp    -0x11f8(%rbp),%rsi
  7b770f:	movq   $0x0,-0x1200(%rbp)
  7b771a:	ja     7b78b3 <_Z10acl_reloadP3THD+0x2813>
  7b7720:	mov    0x8d0(%r12),%rax
  7b7728:	mov    -0x2430(%rbp),%rcx
  7b772f:	mov    %rax,-0x2418(%rbp)
  7b7736:	mov    (%r12),%rax
  7b773a:	add    $0x10,%rcx
  7b773e:	mov    %rcx,-0x2480(%rbp)
  7b7745:	mov    %rax,%rdx
  7b7748:	shl    $0x8,%rax
  7b774c:	shl    $0x5,%rdx
  7b7750:	cmp    %rdx,%rax
  7b7753:	jne    7b77c9 <_Z10acl_reloadP3THD+0x2729>
  7b7755:	jmpq   7b78c7 <_Z10acl_reloadP3THD+0x2827>
  7b775a:	nopw   0x0(%rax,%rax,1)
  7b7760:	mov    -0x930(%rbp),%rcx
  7b7767:	lea    0x1(%rax),%rdx
  7b776b:	mov    %rdx,-0x1200(%rbp)
  7b7772:	mov    %rax,%rdx
  7b7775:	shl    $0x8,%rax
  7b7779:	shl    $0x5,%rdx
  7b777d:	sub    %rdx,%rax
  7b7780:	add    %rcx,%rax
  7b7783:	je     7b7797 <_Z10acl_reloadP3THD+0x26f7>
  7b7785:	mov    $0x1c,%ecx
  7b778a:	mov    %rax,%rdi
  7b778d:	mov    -0x2418(%rbp),%rsi
  7b7794:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b7797:	mov    (%r12),%rax
  7b779b:	addq   $0xe0,-0x2418(%rbp)
  7b77a6:	mov    %rax,%rdx
  7b77a9:	shl    $0x8,%rax
  7b77ad:	shl    $0x5,%rdx
  7b77b1:	sub    %rdx,%rax
  7b77b4:	add    0x8d0(%r12),%rax
  7b77bc:	cmp    %rax,-0x2418(%rbp)
  7b77c3:	je     7b78c7 <_Z10acl_reloadP3THD+0x2827>
  7b77c9:	mov    -0x1200(%rbp),%rax
  7b77d0:	cmp    -0x11f8(%rbp),%rax
  7b77d7:	jne    7b7760 <_Z10acl_reloadP3THD+0x26c0>
  7b77d9:	lea    (%rax,%rax,1),%rcx
  7b77dd:	cmp    %rcx,%rax
  7b77e0:	mov    %rcx,-0x2478(%rbp)
  7b77e7:	jae    7b7760 <_Z10acl_reloadP3THD+0x26c0>
  7b77ed:	mov    %rax,%rdx
  7b77f0:	mov    -0x928(%rbp),%edi
  7b77f6:	shl    $0x9,%rax
  7b77fa:	shl    $0x6,%rdx
  7b77fe:	mov    %rax,%rsi
  7b7801:	sub    %rdx,%rsi
  7b7804:	mov    $0x10,%edx
  7b7809:	callq  eb5ec0 <my_malloc>
  7b780e:	test   %rax,%rax
  7b7811:	mov    %rax,-0x2470(%rbp)
  7b7818:	je     7b7797 <_Z10acl_reloadP3THD+0x26f7>
  7b781e:	mov    -0x1200(%rbp),%rcx
  7b7825:	mov    -0x930(%rbp),%rdi
  7b782c:	test   %rcx,%rcx
  7b782f:	je     7b7877 <_Z10acl_reloadP3THD+0x27d7>
  7b7831:	mov    -0x2470(%rbp),%r9
  7b7838:	xor    %r8d,%r8d
  7b783b:	mov    $0x1c,%edx
  7b7840:	mov    %r9,%rax
  7b7843:	mov    %rax,%rsi
  7b7846:	sub    %r9,%rsi
  7b7849:	add    %rdi,%rsi
  7b784c:	test   %rax,%rax
  7b784f:	je     7b7868 <_Z10acl_reloadP3THD+0x27c8>
  7b7851:	mov    %rax,%rdi
  7b7854:	mov    %rdx,%rcx
  7b7857:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b785a:	mov    -0x930(%rbp),%rdi
  7b7861:	mov    -0x1200(%rbp),%rcx
  7b7868:	add    $0x1,%r8
  7b786c:	add    $0xe0,%rax
  7b7872:	cmp    %rcx,%r8
  7b7875:	jb     7b7843 <_Z10acl_reloadP3THD+0x27a3>
  7b7877:	cmp    -0x2480(%rbp),%rdi
  7b787e:	je     7b788c <_Z10acl_reloadP3THD+0x27ec>
  7b7880:	callq  eb6000 <my_free>
  7b7885:	mov    -0x1200(%rbp),%rcx
  7b788c:	mov    -0x2470(%rbp),%rsi
  7b7893:	mov    -0x2478(%rbp),%rax
  7b789a:	mov    %rsi,-0x930(%rbp)
  7b78a1:	mov    %rax,-0x11f8(%rbp)
  7b78a8:	mov    %rcx,%rax
  7b78ab:	mov    %rsi,%rcx
  7b78ae:	jmpq   7b7767 <_Z10acl_reloadP3THD+0x26c7>
  7b78b3:	mov    -0x2430(%rbp),%rdi
  7b78ba:	callq  7ae070 <_ZN16Prealloced_arrayI8ACL_USERLm10ELb1EE7reserveEm.part.141>
  7b78bf:	test   %al,%al
  7b78c1:	je     7b7720 <_Z10acl_reloadP3THD+0x2680>
  7b78c7:	movq   $0x0,(%r12)
  7b78cf:	mov    -0x918(%rbp),%rsi
  7b78d6:	cmp    0x8(%r12),%rsi
  7b78db:	ja     7b7a54 <_Z10acl_reloadP3THD+0x29b4>
  7b78e1:	mov    -0x50(%rbp),%rax
  7b78e5:	mov    %rax,-0x2418(%rbp)
  7b78ec:	mov    -0x920(%rbp),%rax
  7b78f3:	mov    -0x2418(%rbp),%rdi
  7b78fa:	mov    %rax,%rdx
  7b78fd:	shl    $0x8,%rax
  7b7901:	shl    $0x5,%rdx
  7b7905:	cmp    %rdx,%rax
  7b7908:	jne    7b7979 <_Z10acl_reloadP3THD+0x28d9>
  7b790a:	jmpq   7b7a68 <_Z10acl_reloadP3THD+0x29c8>
  7b790f:	nop
  7b7910:	mov    0x8d0(%r12),%rcx
  7b7918:	lea    0x1(%rax),%rdx
  7b791c:	mov    %rdx,(%r12)
  7b7920:	mov    %rax,%rdx
  7b7923:	shl    $0x8,%rax
  7b7927:	shl    $0x5,%rdx
  7b792b:	sub    %rdx,%rax
  7b792e:	add    %rcx,%rax
  7b7931:	je     7b7945 <_Z10acl_reloadP3THD+0x28a5>
  7b7933:	mov    %rax,%rdi
  7b7936:	mov    -0x2418(%rbp),%rsi
  7b793d:	mov    $0x1c,%ecx
  7b7942:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b7945:	mov    -0x920(%rbp),%rax
  7b794c:	mov    -0x50(%rbp),%rdi
  7b7950:	addq   $0xe0,-0x2418(%rbp)
  7b795b:	mov    %rax,%rdx
  7b795e:	shl    $0x8,%rax
  7b7962:	shl    $0x5,%rdx
  7b7966:	sub    %rdx,%rax
  7b7969:	add    %rdi,%rax
  7b796c:	cmp    %rax,-0x2418(%rbp)
  7b7973:	je     7b7a68 <_Z10acl_reloadP3THD+0x29c8>
  7b7979:	mov    (%r12),%rax
  7b797d:	cmp    0x8(%r12),%rax
  7b7982:	jne    7b7910 <_Z10acl_reloadP3THD+0x2870>
  7b7984:	lea    (%rax,%rax,1),%rcx
  7b7988:	cmp    %rcx,%rax
  7b798b:	mov    %rcx,-0x2478(%rbp)
  7b7992:	jae    7b7910 <_Z10acl_reloadP3THD+0x2870>
  7b7998:	mov    %rax,%rdx
  7b799b:	mov    0x8d8(%r12),%edi
  7b79a3:	shl    $0x9,%rax
  7b79a7:	shl    $0x6,%rdx
  7b79ab:	mov    %rax,%rsi
  7b79ae:	sub    %rdx,%rsi
  7b79b1:	mov    $0x10,%edx
  7b79b6:	callq  eb5ec0 <my_malloc>
  7b79bb:	test   %rax,%rax
  7b79be:	mov    %rax,-0x2470(%rbp)
  7b79c5:	je     7b7945 <_Z10acl_reloadP3THD+0x28a5>
  7b79cb:	mov    (%r12),%rcx
  7b79cf:	mov    0x8d0(%r12),%rdi
  7b79d7:	test   %rcx,%rcx
  7b79da:	je     7b7a1c <_Z10acl_reloadP3THD+0x297c>
  7b79dc:	mov    -0x2470(%rbp),%r8
  7b79e3:	xor    %edx,%edx
  7b79e5:	mov    %r8,%rax
  7b79e8:	mov    %rax,%rsi
  7b79eb:	sub    %r8,%rsi
  7b79ee:	add    %rdi,%rsi
  7b79f1:	test   %rax,%rax
  7b79f4:	je     7b7a0d <_Z10acl_reloadP3THD+0x296d>
  7b79f6:	mov    %rax,%rdi
  7b79f9:	mov    $0x1c,%ecx
  7b79fe:	rep movsq %ds:(%rsi),%es:(%rdi)
  7b7a01:	mov    0x8d0(%r12),%rdi
  7b7a09:	mov    (%r12),%rcx
  7b7a0d:	add    $0x1,%rdx
  7b7a11:	add    $0xe0,%rax
  7b7a17:	cmp    %rcx,%rdx
  7b7a1a:	jb     7b79e8 <_Z10acl_reloadP3THD+0x2948>
  7b7a1c:	cmp    %rdi,-0x2468(%rbp)
  7b7a23:	je     7b7a2e <_Z10acl_reloadP3THD+0x298e>
  7b7a25:	callq  eb6000 <my_free>
  7b7a2a:	mov    (%r12),%rcx
  7b7a2e:	mov    -0x2470(%rbp),%rsi
  7b7a35:	mov    -0x2478(%rbp),%rax
  7b7a3c:	mov    %rsi,0x8d0(%r12)
  7b7a44:	mov    %rax,0x8(%r12)
  7b7a49:	mov    %rcx,%rax
  7b7a4c:	mov    %rsi,%rcx
  7b7a4f:	jmpq   7b7918 <_Z10acl_reloadP3THD+0x2878>
  7b7a54:	mov    %r12,%rdi
  7b7a57:	callq  7ae070 <_ZN16Prealloced_arrayI8ACL_USERLm10ELb1EE7reserveEm.part.141>
  7b7a5c:	test   %al,%al
  7b7a5e:	je     7b78e1 <_Z10acl_reloadP3THD+0x2841>
  7b7a64:	mov    -0x50(%rbp),%rdi
  7b7a68:	add    $0x10,%r13
  7b7a6c:	cmp    %r13,%rdi
  7b7a6f:	je     7b6ca0 <_Z10acl_reloadP3THD+0x1c00>
  7b7a75:	callq  eb6000 <my_free>
  7b7a7a:	jmpq   7b6ca0 <_Z10acl_reloadP3THD+0x1c00>
  7b7a7f:	mov    (%rdi),%rax
  7b7a82:	callq  *0xe0(%rax)
  7b7a88:	jmpq   7b6d32 <_Z10acl_reloadP3THD+0x1c92>
  7b7a8d:	mov    %r12,%rax
  7b7a90:	add    $0x40,%r12
  7b7a94:	cmp    %r12,-0x2418(%rbp)
  7b7a9b:	mov    -0x2430(%rbp),%rcx
  7b7aa2:	mov    %r13,(%rax)
  7b7aa5:	mov    %r11,0x8(%rax)
  7b7aa9:	mov    %r10,0x10(%rax)
  7b7aad:	mov    %r9,0x18(%rax)
  7b7ab1:	mov    %rsi,0x20(%rax)
  7b7ab5:	mov    %r8,0x28(%rax)
  7b7ab9:	mov    %rdi,0x30(%rax)
  7b7abd:	mov    %rcx,0x38(%rax)
  7b7ac1:	jne    7b7f85 <_Z10acl_reloadP3THD+0x2ee5>
  7b7ac7:	lea    0x1666612(%rip),%rax        # 1e1e0e0 <acl_dbs>
  7b7ace:	mov    (%rax),%rdi
  7b7ad1:	callq  7b9c40 <_ZN16Prealloced_arrayI6ACL_DBLm10ELb1EE13shrink_to_fitEv>
  7b7ad6:	lea    0x1666613(%rip),%rax        # 1e1e0f0 <acl_proxy_users>
  7b7add:	mov    (%rax),%rax
  7b7ae0:	movq   $0x0,(%rax)
  7b7ae7:	mov    -0x16c0(%rbp),%r13
  7b7aee:	test   %r13,%r13
  7b7af1:	je     7b82e6 <_Z10acl_reloadP3THD+0x3246>
  7b7af7:	mov    -0x2420(%rbp),%rdi
  7b7afe:	xor    %ecx,%ecx
  7b7b00:	movl   $0x0,(%rsp)
  7b7b07:	mov    $0x1,%r9d
  7b7b0d:	mov    $0x1,%r8d
  7b7b13:	mov    %r13,%rdx
  7b7b16:	mov    %r14,%rsi
  7b7b19:	callq  bfe770 <_Z16init_read_recordP11READ_RECORDP3THDP5TABLEP7QEP_TABibb>
  7b7b1e:	test   %al,%al
  7b7b20:	jne    7b6590 <_Z10acl_reloadP3THD+0x14f0>
  7b7b26:	mov    0x0(%r13),%rax
  7b7b2a:	mov    0x8(%r13),%rdi
  7b7b2e:	add    $0x1c0,%rax
  7b7b34:	test   %rdi,%rdi
  7b7b37:	mov    %rax,0x1a8(%r13)
  7b7b3e:	mov    %rax,0x1b0(%r13)
  7b7b45:	je     7b7b55 <_Z10acl_reloadP3THD+0x2ab5>
  7b7b47:	cmpb   $0x0,0x7ff(%r13)
  7b7b4f:	jne    7b832b <_Z10acl_reloadP3THD+0x328b>
  7b7b55:	lea    -0x2390(%rbp),%rax
  7b7b5c:	mov    %rbx,-0x2418(%rbp)
  7b7b63:	mov    %rax,-0x2430(%rbp)
  7b7b6a:	movzbl -0x2424(%rbp),%eax
  7b7b71:	mov    %eax,-0x2424(%rbp)
  7b7b77:	mov    -0x2420(%rbp),%rdi
  7b7b7e:	callq  *-0x2308(%rbp)
  7b7b84:	test   %eax,%eax
  7b7b86:	jne    7b7cad <_Z10acl_reloadP3THD+0x2c0d>
  7b7b8c:	mov    -0x2430(%rbp),%rbx
  7b7b93:	mov    %r15,%rdx
  7b7b96:	mov    %r13,%rsi
  7b7b99:	mov    %rbx,%rdi
  7b7b9c:	callq  7afd10 <_ZN14ACL_PROXY_USER4initEP5TABLEP11st_mem_root>
  7b7ba1:	mov    -0x2424(%rbp),%esi
  7b7ba7:	mov    %rbx,%rdi
  7b7baa:	callq  7afe40 <_ZN14ACL_PROXY_USER14check_validityEb>
  7b7baf:	test   %al,%al
  7b7bb1:	jne    7b7b77 <_Z10acl_reloadP3THD+0x2ad7>
  7b7bb3:	lea    0x1666536(%rip),%rax        # 1e1e0f0 <acl_proxy_users>
  7b7bba:	mov    (%rax),%rbx
  7b7bbd:	mov    (%rbx),%rdx
  7b7bc0:	cmp    0x8(%rbx),%rdx
  7b7bc4:	mov    %rdx,%rax
  7b7bc7:	je     7b7ea6 <_Z10acl_reloadP3THD+0x2e06>
  7b7bcd:	lea    (%rax,%rax,2),%rcx
  7b7bd1:	mov    0x420(%rbx),%rdx
  7b7bd8:	lea    0x1(%rax),%rsi
  7b7bdc:	lea    (%rax,%rcx,4),%rax
  7b7be0:	mov    %rsi,(%rbx)
  7b7be3:	lea    (%rdx,%rax,8),%rax
  7b7be7:	test   %rax,%rax
  7b7bea:	je     7b7b77 <_Z10acl_reloadP3THD+0x2ad7>
  7b7bec:	mov    -0x2390(%rbp),%rdx
  7b7bf3:	mov    %rdx,(%rax)
  7b7bf6:	mov    -0x2388(%rbp),%rdx
  7b7bfd:	mov    %rdx,0x8(%rax)
  7b7c01:	mov    -0x2380(%rbp),%rdx
  7b7c08:	mov    %rdx,0x10(%rax)
  7b7c0c:	mov    -0x2378(%rbp),%rdx
  7b7c13:	mov    %rdx,0x18(%rax)
  7b7c17:	mov    -0x2370(%rbp),%rdx
  7b7c1e:	mov    %rdx,0x20(%rax)
  7b7c22:	mov    -0x2368(%rbp),%rdx
  7b7c29:	mov    %rdx,0x28(%rax)
  7b7c2d:	mov    -0x2360(%rbp),%rdx
  7b7c34:	mov    %rdx,0x30(%rax)
  7b7c38:	mov    -0x2358(%rbp),%rdx
  7b7c3f:	mov    %rdx,0x38(%rax)
  7b7c43:	mov    -0x2350(%rbp),%rdx
  7b7c4a:	mov    %rdx,0x40(%rax)
  7b7c4e:	mov    -0x2348(%rbp),%rdx
  7b7c55:	mov    %rdx,0x48(%rax)
  7b7c59:	mov    -0x2340(%rbp),%rdx
  7b7c60:	mov    %rdx,0x50(%rax)
  7b7c64:	mov    -0x2338(%rbp),%rdx
  7b7c6b:	mov    %rdx,0x58(%rax)
  7b7c6f:	mov    -0x2330(%rbp),%rdx
  7b7c76:	mov    %rdx,0x60(%rax)
  7b7c7a:	jmpq   7b7b77 <_Z10acl_reloadP3THD+0x2ad7>
  7b7c7f:	mov    %r13,%rdi
  7b7c82:	callq  7ae070 <_ZN16Prealloced_arrayI8ACL_USERLm10ELb1EE7reserveEm.part.141>
  7b7c87:	test   %al,%al
  7b7c89:	jne    7b7703 <_Z10acl_reloadP3THD+0x2663>
  7b7c8f:	mov    -0x930(%rbp),%rax
  7b7c96:	mov    %rax,-0x2418(%rbp)
  7b7c9d:	jmpq   7b7595 <_Z10acl_reloadP3THD+0x24f5>
  7b7ca2:	nopw   0x0(%rax,%rax,1)
  7b7ca8:	callq  762130 <__stack_chk_fail@plt>
  7b7cad:	mov    -0x2420(%rbp),%rdi
  7b7cb4:	mov    %eax,%r12d
  7b7cb7:	mov    -0x2418(%rbp),%rbx
  7b7cbe:	callq  bfeeb0 <_Z15end_read_recordP11READ_RECORD>
  7b7cc3:	test   %r12d,%r12d
  7b7cc6:	jg     7b6590 <_Z10acl_reloadP3THD+0x14f0>
  7b7ccc:	lea    0x166641d(%rip),%rax        # 1e1e0f0 <acl_proxy_users>
  7b7cd3:	mov    (%rax),%rax
  7b7cd6:	imul   $0x68,(%rax),%r12
  7b7cda:	mov    0x420(%rax),%r13
  7b7ce1:	add    %r13,%r12
  7b7ce4:	cmp    %r12,%r13
  7b7ce7:	je     7b80d7 <_Z10acl_reloadP3THD+0x3037>
  7b7ced:	mov    %r12,%r15
  7b7cf0:	movabs $0x4ec4ec4ec4ec4ec5,%rdx
  7b7cfa:	mov    %r12,%rsi
  7b7cfd:	sub    %r13,%r15
  7b7d00:	mov    %r13,%rdi
  7b7d03:	mov    %r15,%rax
  7b7d06:	sar    $0x3,%rax
  7b7d0a:	imul   %rdx,%rax
  7b7d0e:	mov    $0x3f,%edx
  7b7d13:	bsr    %rax,%rax
  7b7d17:	xor    $0x3f,%rax
  7b7d1b:	cltq   
  7b7d1d:	sub    %rax,%rdx
  7b7d20:	add    %rdx,%rdx
  7b7d23:	callq  7b4a10 <_ZSt16__introsort_loopIP14ACL_PROXY_USERlN12_GLOBAL__N_111ACL_compareEEvT_S4_T0_T1_.isra.179>
  7b7d28:	cmp    $0x6e7,%r15
  7b7d2f:	jle    7b80cc <_Z10acl_reloadP3THD+0x302c>
  7b7d35:	lea    0x680(%r13),%r15
  7b7d3c:	mov    %r13,%rdi
  7b7d3f:	mov    %r15,%rsi
  7b7d42:	callq  7ae340 <_ZSt16__insertion_sortIP14ACL_PROXY_USERN12_GLOBAL__N_111ACL_compareEEvT_S4_T0_.isra.180>
  7b7d47:	cmp    %r15,%r12
  7b7d4a:	je     7b80d7 <_Z10acl_reloadP3THD+0x3037>
  7b7d50:	mov    %r15,%rdi
  7b7d53:	add    $0x68,%r15
  7b7d57:	callq  7ad4f0 <_ZSt25__unguarded_linear_insertIP14ACL_PROXY_USERN12_GLOBAL__N_111ACL_compareEEvT_T0_.isra.24>
  7b7d5c:	jmp    7b7d47 <_Z10acl_reloadP3THD+0x2ca7>
  7b7d5e:	lea    0x40(%r13),%rax
  7b7d62:	cmp    %rax,-0x2418(%rbp)
  7b7d69:	je     7b7ac7 <_Z10acl_reloadP3THD+0x2a27>
  7b7d6f:	lea    0x80(%r13),%rcx
  7b7d76:	mov    %rax,%r12
  7b7d79:	mov    %rcx,-0x2430(%rbp)
  7b7d80:	jmpq   7b7e86 <_Z10acl_reloadP3THD+0x2de6>
  7b7d85:	mov    0x18(%r12),%rax
  7b7d8a:	mov    %r12,%rdx
  7b7d8d:	mov    (%r12),%r11
  7b7d91:	sub    %r13,%rdx
  7b7d94:	mov    0x8(%r12),%r10
  7b7d99:	mov    0x10(%r12),%r9
  7b7d9e:	sar    $0x6,%rdx
  7b7da2:	mov    -0x2430(%rbp),%rcx
  7b7da9:	mov    %rax,-0x2458(%rbp)
  7b7db0:	mov    0x28(%r12),%rax
  7b7db5:	test   %rdx,%rdx
  7b7db8:	mov    %rax,-0x2468(%rbp)
  7b7dbf:	mov    0x30(%r12),%rax
  7b7dc4:	mov    %rax,-0x2470(%rbp)
  7b7dcb:	mov    0x38(%r12),%rax
  7b7dd0:	mov    %rax,-0x2478(%rbp)
  7b7dd7:	je     7b7e31 <_Z10acl_reloadP3THD+0x2d91>
  7b7dd9:	mov    %rcx,%rdi
  7b7ddc:	shl    $0x6,%rdx
  7b7de0:	mov    %r13,%rsi
  7b7de3:	sub    %rdx,%rdi
  7b7de6:	mov    %rcx,-0x24a0(%rbp)
  7b7ded:	mov    %r9,-0x2498(%rbp)
  7b7df4:	mov    %r10,-0x2490(%rbp)
  7b7dfb:	mov    %r11,-0x2488(%rbp)
  7b7e02:	mov    %r8,-0x2480(%rbp)
  7b7e09:	callq  761ec0 <memmove@plt>
  7b7e0e:	mov    -0x24a0(%rbp),%rcx
  7b7e15:	mov    -0x2498(%rbp),%r9
  7b7e1c:	mov    -0x2490(%rbp),%r10
  7b7e23:	mov    -0x2488(%rbp),%r11
  7b7e2a:	mov    -0x2480(%rbp),%r8
  7b7e31:	mov    -0x2458(%rbp),%rax
  7b7e38:	mov    %r11,0x0(%r13)
  7b7e3c:	mov    %r10,0x8(%r13)
  7b7e40:	mov    %r9,0x10(%r13)
  7b7e44:	mov    %r8,0x20(%r13)
  7b7e48:	mov    %rax,0x18(%r13)
  7b7e4c:	mov    -0x2468(%rbp),%rax
  7b7e53:	mov    %rax,0x28(%r13)
  7b7e57:	mov    -0x2470(%rbp),%rax
  7b7e5e:	mov    %rax,0x30(%r13)
  7b7e62:	mov    -0x2478(%rbp),%rax
  7b7e69:	mov    %rax,0x38(%r13)
  7b7e6d:	addq   $0x40,-0x2430(%rbp)
  7b7e75:	add    $0x40,%r12
  7b7e79:	cmp    %rcx,-0x2418(%rbp)
  7b7e80:	je     7b7ac7 <_Z10acl_reloadP3THD+0x2a27>
  7b7e86:	mov    0x20(%r12),%r8
  7b7e8b:	cmp    0x20(%r13),%r8
  7b7e8f:	ja     7b7d85 <_Z10acl_reloadP3THD+0x2ce5>
  7b7e95:	mov    %r12,%rdi
  7b7e98:	callq  763669 <_ZSt25__unguarded_linear_insertIP6ACL_DBN12_GLOBAL__N_111ACL_compareEEvT_T0_.isra.22>
  7b7e9d:	mov    -0x2430(%rbp),%rcx
  7b7ea4:	jmp    7b7e6d <_Z10acl_reloadP3THD+0x2dcd>
  7b7ea6:	lea    (%rdx,%rdx,1),%r12
  7b7eaa:	cmp    %r12,%rdx
  7b7ead:	jae    7b7bcd <_Z10acl_reloadP3THD+0x2b2d>
  7b7eb3:	imul   $0x68,%r12,%rsi
  7b7eb7:	mov    0x428(%rbx),%edi
  7b7ebd:	mov    $0x10,%edx
  7b7ec2:	callq  eb5ec0 <my_malloc>
  7b7ec7:	test   %rax,%rax
  7b7eca:	je     7b8059 <_Z10acl_reloadP3THD+0x2fb9>
  7b7ed0:	cmpq   $0x0,(%rbx)
  7b7ed4:	je     7b8023 <_Z10acl_reloadP3THD+0x2f83>
  7b7eda:	mov    0x420(%rbx),%rdi
  7b7ee1:	mov    %rax,%rdx
  7b7ee4:	xor    %r8d,%r8d
  7b7ee7:	mov    %rdx,%rcx
  7b7eea:	sub    %rax,%rcx
  7b7eed:	add    %rdi,%rcx
  7b7ef0:	test   %rdx,%rdx
  7b7ef3:	je     7b7f62 <_Z10acl_reloadP3THD+0x2ec2>
  7b7ef5:	mov    (%rcx),%rsi
  7b7ef8:	mov    %rsi,(%rdx)
  7b7efb:	mov    0x8(%rcx),%rsi
  7b7eff:	mov    %rsi,0x8(%rdx)
  7b7f03:	mov    0x10(%rcx),%rsi
  7b7f07:	mov    %rsi,0x10(%rdx)
  7b7f0b:	mov    0x18(%rcx),%rsi
  7b7f0f:	mov    %rsi,0x18(%rdx)
  7b7f13:	mov    0x20(%rcx),%rsi
  7b7f17:	mov    %rsi,0x20(%rdx)
  7b7f1b:	mov    0x28(%rcx),%rsi
  7b7f1f:	mov    %rsi,0x28(%rdx)
  7b7f23:	mov    0x30(%rcx),%rsi
  7b7f27:	mov    %rsi,0x30(%rdx)
  7b7f2b:	mov    0x38(%rcx),%rsi
  7b7f2f:	mov    %rsi,0x38(%rdx)
  7b7f33:	mov    0x40(%rcx),%rsi
  7b7f37:	mov    %rsi,0x40(%rdx)
  7b7f3b:	mov    0x48(%rcx),%rsi
  7b7f3f:	mov    %rsi,0x48(%rdx)
  7b7f43:	mov    0x50(%rcx),%rsi
  7b7f47:	mov    %rsi,0x50(%rdx)
  7b7f4b:	mov    0x58(%rcx),%rsi
  7b7f4f:	mov    %rsi,0x58(%rdx)
  7b7f53:	mov    0x60(%rcx),%rcx
  7b7f57:	mov    %rcx,0x60(%rdx)
  7b7f5b:	mov    0x420(%rbx),%rdi
  7b7f62:	add    $0x1,%r8
  7b7f66:	add    $0x68,%rdx
  7b7f6a:	cmp    (%rbx),%r8
  7b7f6d:	jb     7b7ee7 <_Z10acl_reloadP3THD+0x2e47>
  7b7f73:	jmpq   7b802a <_Z10acl_reloadP3THD+0x2f8a>
  7b7f78:	cmp    %r12,-0x2418(%rbp)
  7b7f7f:	je     7b7ac7 <_Z10acl_reloadP3THD+0x2a27>
  7b7f85:	mov    0x20(%r12),%rsi
  7b7f8a:	cmp    -0x20(%r12),%rsi
  7b7f8f:	mov    0x38(%r12),%rax
  7b7f94:	mov    (%r12),%r13
  7b7f98:	mov    0x8(%r12),%r11
  7b7f9d:	mov    0x10(%r12),%r10
  7b7fa2:	mov    0x18(%r12),%r9
  7b7fa7:	mov    0x28(%r12),%r8
  7b7fac:	mov    %rax,-0x2430(%rbp)
  7b7fb3:	mov    0x30(%r12),%rdi
  7b7fb8:	lea    -0x40(%r12),%rax
  7b7fbd:	jbe    7b7a8d <_Z10acl_reloadP3THD+0x29ed>
  7b7fc3:	mov    %r12,%rdx
  7b7fc6:	jmp    7b7fd6 <_Z10acl_reloadP3THD+0x2f36>
  7b7fc8:	nopl   0x0(%rax,%rax,1)
  7b7fd0:	mov    %rax,%rdx
  7b7fd3:	mov    %rcx,%rax
  7b7fd6:	mov    (%rax),%rcx
  7b7fd9:	mov    %rcx,(%rdx)
  7b7fdc:	mov    0x8(%rax),%rcx
  7b7fe0:	mov    %rcx,0x8(%rdx)
  7b7fe4:	mov    0x10(%rax),%rcx
  7b7fe8:	mov    %rcx,0x10(%rdx)
  7b7fec:	mov    0x18(%rax),%rcx
  7b7ff0:	mov    %rcx,0x18(%rdx)
  7b7ff4:	mov    0x20(%rax),%rcx
  7b7ff8:	mov    %rcx,0x20(%rdx)
  7b7ffc:	mov    0x28(%rax),%rcx
  7b8000:	mov    %rcx,0x28(%rdx)
  7b8004:	mov    0x30(%rax),%rcx
  7b8008:	mov    %rcx,0x30(%rdx)
  7b800c:	mov    0x38(%rax),%rcx
  7b8010:	mov    %rcx,0x38(%rdx)
  7b8014:	cmp    -0x20(%rax),%rsi
  7b8018:	lea    -0x40(%rax),%rcx
  7b801c:	ja     7b7fd0 <_Z10acl_reloadP3THD+0x2f30>
  7b801e:	jmpq   7b7a90 <_Z10acl_reloadP3THD+0x29f0>
  7b8023:	mov    0x420(%rbx),%rdi
  7b802a:	lea    0x10(%rbx),%rdx
  7b802e:	cmp    %rdx,%rdi
  7b8031:	je     7b8046 <_Z10acl_reloadP3THD+0x2fa6>
  7b8033:	mov    %rax,-0x2458(%rbp)
  7b803a:	callq  eb6000 <my_free>
  7b803f:	mov    -0x2458(%rbp),%rax
  7b8046:	mov    %rax,0x420(%rbx)
  7b804d:	mov    %r12,0x8(%rbx)
  7b8051:	mov    (%rbx),%rax
  7b8054:	jmpq   7b7bcd <_Z10acl_reloadP3THD+0x2b2d>
  7b8059:	mov    -0x2420(%rbp),%rdi
  7b8060:	mov    -0x2418(%rbp),%rbx
  7b8067:	callq  bfeeb0 <_Z15end_read_recordP11READ_RECORD>
  7b806c:	jmpq   7b6590 <_Z10acl_reloadP3THD+0x14f0>
  7b8071:	mov    -0x50(%rbp),%rdi
  7b8075:	add    $0x10,%r13
  7b8079:	mov    %rax,%rbx
  7b807c:	cmp    %r13,%rdi
  7b807f:	je     7b8086 <_Z10acl_reloadP3THD+0x2fe6>
  7b8081:	callq  eb6000 <my_free>
  7b8086:	mov    -0x2430(%rbp),%rax
  7b808d:	mov    -0x930(%rbp),%rdi
  7b8094:	add    $0x10,%rax
  7b8098:	cmp    %rax,%rdi
  7b809b:	je     7b80a2 <_Z10acl_reloadP3THD+0x3002>
  7b809d:	callq  eb6000 <my_free>
  7b80a2:	mov    %rbx,%rdi
  7b80a5:	callq  762870 <_Unwind_Resume@plt>
  7b80aa:	mov    %rax,%rbx
  7b80ad:	jmp    7b8086 <_Z10acl_reloadP3THD+0x2fe6>
  7b80af:	cmpq   $0x0,-0x8f0(%rbp)
  7b80b7:	movl   $0x0,-0x8e8(%rbp)
  7b80c1:	jne    7b5eed <_Z10acl_reloadP3THD+0xe4d>
  7b80c7:	jmpq   7b5ef7 <_Z10acl_reloadP3THD+0xe57>
  7b80cc:	mov    %r12,%rsi
  7b80cf:	mov    %r13,%rdi
  7b80d2:	callq  7ae340 <_ZSt16__insertion_sortIP14ACL_PROXY_USERN12_GLOBAL__N_111ACL_compareEEvT_S4_T0_.isra.180>
  7b80d7:	lea    0x1666012(%rip),%rax        # 1e1e0f0 <acl_proxy_users>
  7b80de:	mov    (%rax),%rdi
  7b80e1:	callq  7ba540 <_ZN16Prealloced_arrayI14ACL_PROXY_USERLm10ELb1EE13shrink_to_fitEv>
  7b80e6:	lea    0x15bdba3(%rip),%rax        # 1d75c90 <validate_user_plugins>
  7b80ed:	cmpb   $0x0,(%rax)
  7b80f0:	jne    7b81c7 <_Z10acl_reloadP3THD+0x3127>
  7b80f6:	callq  7b3bf0 <_ZL15init_check_hostv>
  7b80fb:	lea    0x1665dbe(%rip),%rax        # 1e1dec0 <initialized>
  7b8102:	mov    %rbx,%rdi
  7b8105:	movb   $0x1,(%rax)
  7b8108:	mov    -0x2460(%rbp),%rax
  7b810f:	mov    %rax,0x398(%r14)
  7b8116:	mov    (%rbx),%rax
  7b8119:	callq  *0x178(%rax)
  7b811f:	lea    -0x23f0(%rbp),%rdi
  7b8126:	xor    %esi,%esi
  7b8128:	callq  eb1f50 <free_root>
  7b812d:	cmpq   $0x0,-0x2448(%rbp)
  7b8135:	je     7b815f <_Z10acl_reloadP3THD+0x30bf>
  7b8137:	mov    -0x2448(%rbp),%rax
  7b813e:	mov    0x8d0(%rax),%rdi
  7b8145:	add    $0x10,%rax
  7b8149:	cmp    %rax,%rdi
  7b814c:	je     7b8153 <_Z10acl_reloadP3THD+0x30b3>
  7b814e:	callq  eb6000 <my_free>
  7b8153:	mov    -0x2448(%rbp),%rdi
  7b815a:	callq  7625e0 <_ZdlPv@plt>
  7b815f:	mov    -0x2438(%rbp),%rax
  7b8166:	test   %rax,%rax
  7b8169:	je     7b818c <_Z10acl_reloadP3THD+0x30ec>
  7b816b:	mov    0x290(%rax),%rdi
  7b8172:	add    $0x10,%rax
  7b8176:	cmp    %rax,%rdi
  7b8179:	je     7b8180 <_Z10acl_reloadP3THD+0x30e0>
  7b817b:	callq  eb6000 <my_free>
  7b8180:	mov    -0x2438(%rbp),%rdi
  7b8187:	callq  7625e0 <_ZdlPv@plt>
  7b818c:	mov    -0x2440(%rbp),%rax
  7b8193:	test   %rax,%rax
  7b8196:	je     7b81c0 <_Z10acl_reloadP3THD+0x3120>
  7b8198:	mov    0x420(%rax),%rdi
  7b819f:	add    $0x10,%rax
  7b81a3:	cmp    %rax,%rdi
  7b81a6:	je     7b81ad <_Z10acl_reloadP3THD+0x310d>
  7b81a8:	callq  eb6000 <my_free>
  7b81ad:	mov    -0x2440(%rbp),%rdi
  7b81b4:	xor    %ebx,%ebx
  7b81b6:	callq  7625e0 <_ZdlPv@plt>
  7b81bb:	jmpq   7b57de <_Z10acl_reloadP3THD+0x73e>
  7b81c0:	xor    %ebx,%ebx
  7b81c2:	jmpq   7b57de <_Z10acl_reloadP3THD+0x73e>
  7b81c7:	nopw   0x0(%rax,%rax,1)
  7b81d0:	callq  cb7e90 <_Z16lock_plugin_datav>
  7b81d5:	lea    0x1665f24(%rip),%rax        # 1e1e100 <acl_users>
  7b81dc:	mov    (%rax),%rax
  7b81df:	mov    0x8d0(%rax),%r13
  7b81e6:	imul   $0xe0,(%rax),%rax
  7b81ed:	test   %rax,%rax
  7b81f0:	jne    7b822e <_Z10acl_reloadP3THD+0x318e>
  7b81f2:	jmpq   7b8295 <_Z10acl_reloadP3THD+0x31f5>
  7b81f7:	nopw   0x0(%rax,%rax,1)
  7b8200:	lea    0x1665ef9(%rip),%rax        # 1e1e100 <acl_users>
  7b8207:	add    $0xe0,%r13
  7b820e:	mov    (%rax),%rdx
  7b8211:	mov    (%rdx),%rax
  7b8214:	mov    %rax,%rcx
  7b8217:	shl    $0x8,%rax
  7b821b:	shl    $0x5,%rcx
  7b821f:	sub    %rcx,%rax
  7b8222:	add    0x8d0(%rdx),%rax
  7b8229:	cmp    %rax,%r13
  7b822c:	je     7b8295 <_Z10acl_reloadP3THD+0x31f5>
  7b822e:	cmpq   $0x0,0x90(%r13)
  7b8236:	je     7b8200 <_Z10acl_reloadP3THD+0x3160>
  7b8238:	mov    0x88(%r13),%rdi
  7b823f:	callq  7aa890 <_Z23auth_plugin_is_built_inPKc>
  7b8244:	test   %al,%al
  7b8246:	je     7b82a5 <_Z10acl_reloadP3THD+0x3205>
  7b8248:	lea    0x15bda21(%rip),%r12        # 1d75c70 <sha256_password_plugin_name>
  7b824f:	mov    (%r12),%rax
  7b8253:	cmp    %rax,0x88(%r13)
  7b825a:	jne    7b8200 <_Z10acl_reloadP3THD+0x3160>
  7b825c:	callq  7ab880 <_Z15rsa_auth_statusv>
  7b8261:	test   %al,%al
  7b8263:	je     7b8200 <_Z10acl_reloadP3THD+0x3160>
  7b8265:	lea    0x1661e54(%rip),%rax        # 1e1a0c0 <ssl_acceptor_fd>
  7b826c:	cmpq   $0x0,(%rax)
  7b8270:	jne    7b8200 <_Z10acl_reloadP3THD+0x3160>
  7b8272:	mov    0x48(%r13),%rdx
  7b8276:	mov    0x0(%r13),%r8
  7b827a:	lea    0xb67e87(%rip),%rdi        # 1320108 <_ZTS32Find_thd_by_id_with_callback_setItE+0xc68>
  7b8281:	mov    0x8(%r13),%ecx
  7b8285:	mov    (%r12),%rsi
  7b8289:	xor    %eax,%eax
  7b828b:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b8290:	jmpq   7b8200 <_Z10acl_reloadP3THD+0x3160>
  7b8295:	callq  cb7f10 <_Z18unlock_plugin_datav>
  7b829a:	nopw   0x0(%rax,%rax,1)
  7b82a0:	jmpq   7b80f6 <_Z10acl_reloadP3THD+0x3056>
  7b82a5:	lea    0x88(%r13),%rdi
  7b82ac:	mov    $0x7,%esi
  7b82b1:	callq  cb7de0 <_Z19plugin_find_by_typeRK25st_mysql_const_lex_stringi>
  7b82b6:	test   %rax,%rax
  7b82b9:	jne    7b8248 <_Z10acl_reloadP3THD+0x31a8>
  7b82bb:	mov    0x48(%r13),%rcx
  7b82bf:	mov    0x88(%r13),%rdx
  7b82c6:	lea    0xb67dc3(%rip),%rdi        # 1320090 <_ZTS32Find_thd_by_id_with_callback_setItE+0xbf0>
  7b82cd:	mov    0x0(%r13),%r9
  7b82d1:	mov    0x8(%r13),%r8d
  7b82d5:	mov    0x90(%r13),%esi
  7b82dc:	callq  be8180 <_Z17sql_print_warningPKcz>
  7b82e1:	jmpq   7b8248 <_Z10acl_reloadP3THD+0x31a8>
  7b82e6:	lea    0xb67d53(%rip),%rdi        # 1320040 <_ZTS32Find_thd_by_id_with_callback_setItE+0xba0>
  7b82ed:	xor    %eax,%eax
  7b82ef:	callq  be5b90 <_Z15sql_print_errorPKcz>
  7b82f4:	jmpq   7b80d7 <_Z10acl_reloadP3THD+0x3037>
  7b82f9:	cmpb   $0x0,-0x2374(%rbp)
  7b8300:	mov    %rax,%rbx
  7b8303:	je     7b80a2 <_Z10acl_reloadP3THD+0x3002>
  7b8309:	mov    -0x2390(%rbp),%rdi
  7b8310:	movb   $0x0,-0x2374(%rbp)
  7b8317:	movl   $0x0,-0x2378(%rbp)
  7b8321:	callq  eb6000 <my_free>
  7b8326:	jmpq   7b80a2 <_Z10acl_reloadP3THD+0x3002>
  7b832b:	mov    (%rdi),%rax
  7b832e:	callq  *0xe0(%rax)
  7b8334:	jmpq   7b7b55 <_Z10acl_reloadP3THD+0x2ab5>
  7b8339:	nopl   0x0(%rax)
