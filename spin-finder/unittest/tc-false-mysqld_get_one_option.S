// TC_OUT
00000000007967d0 <mysqld_get_one_option>:
  7967d0:	push   %rbp
  7967d1:	mov    %rsp,%rbp
  7967d4:	push   %r14
  7967d6:	push   %r13
  7967d8:	push   %r12
  7967da:	push   %rbx
  7967db:	sub    $0xa0,%rsp
  7967e2:	mov    %fs:0x28,%rax
  7967eb:	mov    %rax,-0x28(%rbp)
  7967ef:	xor    %eax,%eax
  7967f1:	lea    -0x23(%rdi),%eax
  7967f4:	cmp    $0x11d,%eax
  7967f9:	ja     796830 <mysqld_get_one_option+0x60>
  7967fb:	lea    0xb81b56(%rip),%rcx        # 1318358 <_IO_stdin_used+0x3118>
  796802:	mov    %rdx,%rbx
  796805:	movslq (%rcx,%rax,4),%rax
  796809:	add    %rax,%rcx
  79680c:	jmpq   *%rcx
  79680e:	lea    0x168518b(%rip),%rax        # 1e1b9a0 <rpl_filter>
  796815:	mov    %rdx,%rsi
  796818:	mov    (%rax),%rdi
  79681b:	callq  e5ced0 <_ZN10Rpl_filter17add_wild_do_tableEPKc>
  796820:	test   %eax,%eax
  796822:	jne    796bf1 <mysqld_get_one_option+0x421>
  796828:	nopl   0x0(%rax,%rax,1)
  796830:	xor    %eax,%eax
  796832:	nopw   0x0(%rax,%rax,1)
  796838:	mov    -0x28(%rbp),%rsi
  79683c:	xor    %fs:0x28,%rsi
  796845:	jne    7971de <mysqld_get_one_option+0xa0e>
  79684b:	add    $0xa0,%rsp
  796852:	pop    %rbx
  796853:	pop    %r12
  796855:	pop    %r13
  796857:	pop    %r14
  796859:	pop    %rbp
  79685a:	retq   
  79685b:	lea    0xb82bbe(%rip),%rdi        # 1319420 <log_10+0xc40>
  796862:	xor    %eax,%eax
  796864:	callq  be8180 <_Z17sql_print_warningPKcz>
  796869:	lea    0xb7eba0(%rip),%rsi        # 1315410 <_IO_stdin_used+0x1d0>
  796870:	xor    %edi,%edi
  796872:	callq  c5ef90 <_Z35push_deprecated_warn_no_replacementP3THDPKc>
  796877:	xor    %eax,%eax
  796879:	jmp    796838 <mysqld_get_one_option+0x68>
  79687b:	lea    0xb7ea9f(%rip),%rdx        # 1315321 <_IO_stdin_used+0xe1>
  796882:	lea    0xb7eaac(%rip),%rsi        # 1315335 <_IO_stdin_used+0xf5>
  796889:	xor    %edi,%edi
  79688b:	callq  c5ef20 <_Z20push_deprecated_warnP3THDPKcS2_>
  796890:	mov    %rbx,%rsi
  796893:	lea    0x1685d26(%rip),%rbx        # 1e1c5c0 <lc_messages_dir>
  79689a:	mov    $0x1ff,%edx
  79689f:	mov    %rbx,%rdi
  7968a2:	callq  1313900 <strmake>
  7968a7:	lea    0x1685ab2(%rip),%rax        # 1e1c360 <lc_messages_dir_ptr>
  7968ae:	mov    %rbx,(%rax)
  7968b1:	xor    %eax,%eax
  7968b3:	jmp    796838 <mysqld_get_one_option+0x68>
  7968b5:	xor    %eax,%eax
  7968b7:	test   %rdx,%rdx
  7968ba:	je     7968cb <mysqld_get_one_option+0xfb>
  7968bc:	mov    $0xa,%edx
  7968c1:	xor    %esi,%esi
  7968c3:	mov    %rbx,%rdi
  7968c6:	callq  762dc0 <strtol@plt>
  7968cb:	lea    0x1686c0e(%rip),%rdx        # 1e1d4e0 <test_flags>
  7968d2:	mov    %eax,(%rdx)
  7968d4:	lea    0x1686e55(%rip),%rax        # 1e1d730 <opt_endinfo>
  7968db:	movb   $0x1,(%rax)
  7968de:	xor    %eax,%eax
  7968e0:	jmpq   796838 <mysqld_get_one_option+0x68>
  7968e5:	orq    $0x200,0x1687010(%rip)        # 1e1d900 <_ZL15opt_specialflag>
  7968f0:	xor    %eax,%eax
  7968f2:	jmpq   796838 <mysqld_get_one_option+0x68>
  7968f7:	cmpb   $0x0,(%rdx)
  7968fa:	je     797045 <mysqld_get_one_option+0x875>
  796900:	mov    %rdx,%rdi
  796903:	callq  cd9af0 <_Z19push_ignored_db_dirPc>
  796908:	test   %al,%al
  79690a:	je     796830 <mysqld_get_one_option+0x60>
  796910:	lea    0xb82a89(%rip),%rdi        # 13193a0 <log_10+0xbc0>
  796917:	xor    %eax,%eax
  796919:	mov    %rbx,%rdx
  79691c:	mov    $0x200,%esi
  796921:	callq  be5b90 <_Z15sql_print_errorPKcz>
  796926:	mov    $0x1,%eax
  79692b:	jmpq   796838 <mysqld_get_one_option+0x68>
  796930:	mov    %rdx,%rdi
  796933:	callq  d1fc20 <_Z43fixup_enforce_gtid_consistency_command_linePc>
  796938:	test   %rax,%rax
  79693b:	je     796830 <mysqld_get_one_option+0x60>
  796941:	lea    0xb82b58(%rip),%rdi        # 13194a0 <log_10+0xcc0>
  796948:	mov    %rax,%rsi
  79694b:	xor    %eax,%eax
  79694d:	callq  be8180 <_Z17sql_print_warningPKcz>
  796952:	xor    %eax,%eax
  796954:	jmpq   796838 <mysqld_get_one_option+0x68>
  796959:	lea    0xb7eac7(%rip),%rsi        # 1315427 <_IO_stdin_used+0x1e7>
  796960:	xor    %edi,%edi
  796962:	callq  c5ef90 <_Z35push_deprecated_warn_no_replacementP3THDPKc>
  796967:	xor    %eax,%eax
  796969:	jmpq   796838 <mysqld_get_one_option+0x68>
  79696e:	lea    0x16850eb(%rip),%rbx        # 1e1ba60 <server_version>
  796975:	lea    0xd95f74(%rip),%rdx        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  79697c:	lea    0xb7e9de(%rip),%rsi        # 1315361 <_IO_stdin_used+0x121>
  796983:	xor    %ecx,%ecx
  796985:	xor    %eax,%eax
  796987:	mov    %rbx,%rdi
  79698a:	callq  1313990 <strxmov>
  79698f:	lea    0x1686e1a(%rip),%rdx        # 1e1d7b0 <opt_general_log>
  796996:	cmpb   $0x0,(%rdx)
  796999:	jne    7969b3 <mysqld_get_one_option+0x1e3>
  79699b:	lea    0x1686dfe(%rip),%rdx        # 1e1d7a0 <opt_slow_log>
  7969a2:	cmpb   $0x0,(%rdx)
  7969a5:	jne    7969b3 <mysqld_get_one_option+0x1e3>
  7969a7:	lea    0x1686e22(%rip),%rdx        # 1e1d7d0 <opt_bin_log>
  7969ae:	cmpb   $0x0,(%rdx)
  7969b1:	je     7969bd <mysqld_get_one_option+0x1ed>
  7969b3:	movl   $0x676f6c2d,(%rax)
  7969b9:	movb   $0x0,0x4(%rax)
  7969bd:	lea    0xb7e9cf(%rip),%rax        # 1315393 <_IO_stdin_used+0x153>
  7969c4:	lea    0xb7e99d(%rip),%r9        # 1315368 <_IO_stdin_used+0x128>
  7969cb:	lea    0xb7e99d(%rip),%r8        # 131536f <_IO_stdin_used+0x12f>
  7969d2:	lea    0xb7e99c(%rip),%rsi        # 1315375 <_IO_stdin_used+0x135>
  7969d9:	mov    $0x1,%edi
  7969de:	mov    %rbx,%rcx
  7969e1:	mov    %rax,(%rsp)
  7969e5:	lea    0x16be874(%rip),%rax        # 1e55260 <my_progname>
  7969ec:	mov    (%rax),%rdx
  7969ef:	xor    %eax,%eax
  7969f1:	callq  7631a0 <__printf_chk@plt>
  7969f6:	xor    %edi,%edi
  7969f8:	callq  7628d0 <exit@plt>
  7969fd:	lea    0x15d833c(%rip),%rax        # 1d6ed40 <_ZL31compiled_default_collation_name>
  796a04:	cmp    %rax,0x1687155(%rip)        # 1e1db60 <_ZL22default_collation_name>
  796a0b:	jne    796830 <mysqld_get_one_option+0x60>
  796a11:	movq   $0x0,0x1687144(%rip)        # 1e1db60 <_ZL22default_collation_name>
  796a1c:	xor    %eax,%eax
  796a1e:	jmpq   796838 <mysqld_get_one_option+0x68>
  796a23:	lea    0xb7e919(%rip),%rsi        # 1315343 <_IO_stdin_used+0x103>
  796a2a:	xor    %edi,%edi
  796a2c:	callq  c5ef90 <_Z35push_deprecated_warn_no_replacementP3THDPKc>
  796a31:	xor    %eax,%eax
  796a33:	jmpq   796838 <mysqld_get_one_option+0x68>
  796a38:	movb   $0x1,0x1687111(%rip)        # 1e1db50 <_ZL18binlog_format_used>
  796a3f:	xor    %eax,%eax
  796a41:	jmpq   796838 <mysqld_get_one_option+0x68>
  796a46:	lea    0x1684f43(%rip),%rax        # 1e1b990 <binlog_filter>
  796a4d:	mov    %rdx,%rsi
  796a50:	mov    (%rax),%rdi
  796a53:	callq  e5cbf0 <_ZN10Rpl_filter9add_do_dbEPKc>
  796a58:	xor    %eax,%eax
  796a5a:	jmpq   796838 <mysqld_get_one_option+0x68>
  796a5f:	mov    0x168714a(%rip),%r12        # 1e1dbb0 <_ZL11mysqld_user>
  796a66:	test   %r12,%r12
  796a69:	je     796a7e <mysqld_get_one_option+0x2ae>
  796a6b:	mov    %rdx,%rsi
  796a6e:	mov    %r12,%rdi
  796a71:	callq  762cc0 <strcmp@plt>
  796a76:	test   %eax,%eax
  796a78:	jne    79706e <mysqld_get_one_option+0x89e>
  796a7e:	mov    %rbx,0x168712b(%rip)        # 1e1dbb0 <_ZL11mysqld_user>
  796a85:	xor    %eax,%eax
  796a87:	jmpq   796838 <mysqld_get_one_option+0x68>
  796a8c:	mov    %rbx,%rsi
  796a8f:	lea    0x1685d2a(%rip),%rbx        # 1e1c7c0 <mysql_real_data_home>
  796a96:	mov    $0x1ff,%edx
  796a9b:	mov    %rbx,%rdi
  796a9e:	callq  1313900 <strmake>
  796aa3:	lea    0x15dd226(%rip),%rax        # 1d73cd0 <mysql_real_data_home_ptr>
  796aaa:	mov    %rbx,(%rax)
  796aad:	xor    %eax,%eax
  796aaf:	jmpq   796838 <mysqld_get_one_option+0x68>
  796ab4:	mov    %rbx,%rsi
  796ab7:	lea    0x1686542(%rip),%rbx        # 1e1d000 <mysql_home>
  796abe:	mov    $0x1ff,%edx
  796ac3:	mov    %rbx,%rdi
  796ac6:	callq  1313900 <strmake>
  796acb:	lea    0x168394e(%rip),%rax        # 1e1a420 <mysql_home_ptr>
  796ad2:	mov    %rbx,(%rax)
  796ad5:	xor    %eax,%eax
  796ad7:	jmpq   796838 <mysqld_get_one_option+0x68>
  796adc:	lea    0x1684b7d(%rip),%rax        # 1e1b660 <global_system_variables>
  796ae3:	movq   $0x40000,0x70(%rax)
  796aeb:	movq   $0x3,0x228(%rax)
  796af6:	xor    %eax,%eax
  796af8:	jmpq   796838 <mysqld_get_one_option+0x68>
  796afd:	lea    0x15f56d4(%rip),%r12        # 1d8c1d8 <opt_plugin_load_list_ptr>
  796b04:	mov    $0x20,%edi
  796b09:	callq  761ea0 <_Znwm@plt>
  796b0e:	lea    0x150cbcb(%rip),%rdx        # 1ca36e0 <_ZTV8i_string>
  796b15:	movq   $0x0,0x8(%rax)
  796b1d:	movq   $0x0,0x10(%rax)
  796b25:	mov    %rbx,0x18(%rax)
  796b29:	add    $0x10,%rdx
  796b2d:	mov    %rdx,(%rax)
  796b30:	mov    (%r12),%rdx
  796b34:	mov    0x10(%rdx),%rcx
  796b38:	mov    %rax,(%rcx)
  796b3b:	lea    0x8(%rdx),%rcx
  796b3f:	add    $0x10,%rax
  796b43:	mov    %rcx,(%rax)
  796b46:	mov    0x10(%rdx),%rcx
  796b4a:	mov    %rcx,-0x8(%rax)
  796b4e:	mov    %rax,0x10(%rdx)
  796b52:	xor    %eax,%eax
  796b54:	jmpq   796838 <mysqld_get_one_option+0x68>
  796b59:	lea    0x1686950(%rip),%rax        # 1e1d4b0 <delay_key_write_options>
  796b60:	orq    $0x2,0x1686d98(%rip)        # 1e1d900 <_ZL15opt_specialflag>
  796b68:	movq   $0x0,(%rax)
  796b6f:	lea    0x173c07a(%rip),%rax        # 1ed2bf0 <myisam_concurrent_insert>
  796b76:	movq   $0x0,(%rax)
  796b7d:	lea    0x173bffc(%rip),%rax        # 1ed2b80 <myisam_recover_options>
  796b84:	movq   $0x10,(%rax)
  796b8b:	lea    0x15d817e(%rip),%rax        # 1d6ed10 <sp_automatic_privileges>
  796b92:	movb   $0x0,(%rax)
  796b95:	lea    0x15fe16c(%rip),%rax        # 1d94d08 <my_enable_symlinks>
  796b9c:	movb   $0x0,(%rax)
  796b9f:	lea    0x168692a(%rip),%rax        # 1e1d4d0 <ha_open_options>
  796ba6:	andl   $0xffffffe7,(%rax)
  796ba9:	lea    0x16867c0(%rip),%rax        # 1e1d370 <query_cache_size>
  796bb0:	movq   $0x0,(%rax)
  796bb7:	xor    %eax,%eax
  796bb9:	jmpq   796838 <mysqld_get_one_option+0x68>
  796bbe:	lea    0x1684ddb(%rip),%rax        # 1e1b9a0 <rpl_filter>
  796bc5:	mov    %rdx,%rsi
  796bc8:	mov    (%rax),%rdi
  796bcb:	callq  e5cc10 <_ZN10Rpl_filter13add_ignore_dbEPKc>
  796bd0:	xor    %eax,%eax
  796bd2:	jmpq   796838 <mysqld_get_one_option+0x68>
  796bd7:	lea    0x1684dc2(%rip),%rax        # 1e1b9a0 <rpl_filter>
  796bde:	mov    %rdx,%rsi
  796be1:	mov    (%rax),%rdi
  796be4:	callq  e5ce30 <_ZN10Rpl_filter18add_do_table_arrayEPKc>
  796be9:	test   %eax,%eax
  796beb:	je     796830 <mysqld_get_one_option+0x60>
  796bf1:	lea    0xb82728(%rip),%rdi        # 1319320 <log_10+0xb40>
  796bf8:	xor    %eax,%eax
  796bfa:	mov    %rbx,%rsi
  796bfd:	callq  be5b90 <_Z15sql_print_errorPKcz>
  796c02:	mov    $0x1,%eax
  796c07:	jmpq   796838 <mysqld_get_one_option+0x68>
  796c0c:	lea    0x1684d8d(%rip),%rax        # 1e1b9a0 <rpl_filter>
  796c13:	mov    %rdx,%rsi
  796c16:	mov    (%rax),%rdi
  796c19:	callq  e5cf20 <_ZN10Rpl_filter21add_wild_ignore_tableEPKc>
  796c1e:	test   %eax,%eax
  796c20:	je     796830 <mysqld_get_one_option+0x60>
  796c26:	lea    0xb8271b(%rip),%rdi        # 1319348 <log_10+0xb68>
  796c2d:	xor    %eax,%eax
  796c2f:	mov    %rbx,%rsi
  796c32:	callq  be5b90 <_Z15sql_print_errorPKcz>
  796c37:	mov    $0x1,%eax
  796c3c:	jmpq   796838 <mysqld_get_one_option+0x68>
  796c41:	lea    0x1150de1(%rip),%rsi        # 18e7a29 <lfactor+0x189>
  796c48:	mov    %rdx,%rdi
  796c4b:	callq  762470 <strstr@plt>
  796c50:	test   %rax,%rax
  796c53:	je     7971c0 <mysqld_get_one_option+0x9f0>
  796c59:	cmp    %rax,%rbx
  796c5c:	lea    0x2(%rax),%rdx
  796c60:	jae    7971d6 <mysqld_get_one_option+0xa06>
  796c66:	lea    0x16194f3(%rip),%rcx        # 1db0160 <my_charset_latin1>
  796c6d:	mov    0x30(%rcx),%rdi
  796c71:	movzbl -0x1(%rax),%ecx
  796c75:	testb  $0x8,0x1(%rdi,%rcx,1)
  796c7a:	mov    %rax,%rcx
  796c7d:	jne    796c93 <mysqld_get_one_option+0x4c3>
  796c7f:	jmp    796c9c <mysqld_get_one_option+0x4cc>
  796c81:	nopl   0x0(%rax)
  796c88:	movzbl -0x1(%rcx),%esi
  796c8c:	testb  $0x8,0x1(%rdi,%rsi,1)
  796c91:	je     796c9c <mysqld_get_one_option+0x4cc>
  796c93:	sub    $0x1,%rcx
  796c97:	cmp    %rbx,%rcx
  796c9a:	jne    796c88 <mysqld_get_one_option+0x4b8>
  796c9c:	movb   $0x0,(%rcx)
  796c9f:	cmpb   $0x0,(%rbx)
  796ca2:	je     797180 <mysqld_get_one_option+0x9b0>
  796ca8:	movzbl 0x2(%rax),%eax
  796cac:	test   %al,%al
  796cae:	je     796ce6 <mysqld_get_one_option+0x516>
  796cb0:	lea    0x16194a9(%rip),%rcx        # 1db0160 <my_charset_latin1>
  796cb7:	mov    0x30(%rcx),%rcx
  796cbb:	testb  $0x8,0x1(%rcx,%rax,1)
  796cc0:	jne    796cdb <mysqld_get_one_option+0x50b>
  796cc2:	jmpq   797055 <mysqld_get_one_option+0x885>
  796cc7:	nopw   0x0(%rax,%rax,1)
  796cd0:	testb  $0x8,0x1(%rcx,%rax,1)
  796cd5:	je     797055 <mysqld_get_one_option+0x885>
  796cdb:	add    $0x1,%rdx
  796cdf:	movzbl (%rdx),%eax
  796ce2:	test   %al,%al
  796ce4:	jne    796cd0 <mysqld_get_one_option+0x500>
  796ce6:	lea    0xb82823(%rip),%rdi        # 1319510 <log_10+0xd30>
  796ced:	xor    %eax,%eax
  796cef:	callq  be5b90 <_Z15sql_print_errorPKcz>
  796cf4:	mov    $0x1,%eax
  796cf9:	jmpq   796838 <mysqld_get_one_option+0x68>
  796cfe:	lea    0x1684c9b(%rip),%rax        # 1e1b9a0 <rpl_filter>
  796d05:	mov    %rdx,%rsi
  796d08:	mov    (%rax),%rdi
  796d0b:	callq  e5ce80 <_ZN10Rpl_filter22add_ignore_table_arrayEPKc>
  796d10:	test   %eax,%eax
  796d12:	je     796830 <mysqld_get_one_option+0x60>
  796d18:	jmpq   796c26 <mysqld_get_one_option+0x456>
  796d1d:	lea    0xb826dc(%rip),%rsi        # 1319400 <log_10+0xc20>
  796d24:	xor    %edi,%edi
  796d26:	callq  c5ef90 <_Z35push_deprecated_warn_no_replacementP3THDPKc>
  796d2b:	xor    %eax,%eax
  796d2d:	jmpq   796838 <mysqld_get_one_option+0x68>
  796d32:	lea    0xb82637(%rip),%rdx        # 1319370 <log_10+0xb90>
  796d39:	lea    0xb7e691(%rip),%rsi        # 13153d1 <_IO_stdin_used+0x191>
  796d40:	xor    %edi,%edi
  796d42:	callq  c5ef20 <_Z20push_deprecated_warnP3THDPKcS2_>
  796d47:	xor    %eax,%eax
  796d49:	jmpq   796838 <mysqld_get_one_option+0x68>
  796d4e:	movb   $0x1,0x1686ebb(%rip)        # 1e1dc10 <_ZL27lower_case_table_names_used>
  796d55:	xor    %eax,%eax
  796d57:	jmpq   796838 <mysqld_get_one_option+0x68>
  796d5c:	movb   $0x1,0x1686bbd(%rip)        # 1e1d920 <_ZL14opt_myisam_log>
  796d63:	xor    %eax,%eax
  796d65:	jmpq   796838 <mysqld_get_one_option+0x68>
  796d6a:	lea    0x168695f(%rip),%rax        # 1e1d6d0 <opt_bootstrap>
  796d71:	movb   $0x1,(%rax)
  796d74:	xor    %eax,%eax
  796d76:	jmpq   796838 <mysqld_get_one_option+0x68>
  796d7b:	lea    0x15fe73e(%rip),%rax        # 1d954c0 <disabled_my_option>
  796d82:	cmp    (%rax),%rdx
  796d85:	lea    0x1686a44(%rip),%rax        # 1e1d7d0 <opt_bin_log>
  796d8c:	setne  (%rax)
  796d8f:	xor    %eax,%eax
  796d91:	jmpq   796838 <mysqld_get_one_option+0x68>
  796d96:	lea    0x1684bf3(%rip),%rax        # 1e1b990 <binlog_filter>
  796d9d:	mov    %rdx,%rsi
  796da0:	mov    (%rax),%rdi
  796da3:	callq  e5cc10 <_ZN10Rpl_filter13add_ignore_dbEPKc>
  796da8:	xor    %eax,%eax
  796daa:	jmpq   796838 <mysqld_get_one_option+0x68>
  796daf:	cmpb   $0x0,(%rdx)
  796db2:	lea    0x1686987(%rip),%rax        # 1e1d740 <server_id_supplied>
  796db9:	setne  (%rax)
  796dbc:	xor    %eax,%eax
  796dbe:	jmpq   796838 <mysqld_get_one_option+0x68>
  796dc3:	lea    0x15f540e(%rip),%r12        # 1d8c1d8 <opt_plugin_load_list_ptr>
  796dca:	mov    (%r12),%rdi
  796dce:	callq  c74510 <_Z9free_listP6I_ListI8i_stringE>
  796dd3:	jmpq   796b04 <mysqld_get_one_option+0x334>
  796dd8:	lea    0x15f53f1(%rip),%r12        # 1d8c1d0 <opt_early_plugin_load_list_ptr>
  796ddf:	jmp    796dca <mysqld_get_one_option+0x5fa>
  796de1:	test   %rdx,%rdx
  796de4:	jne    796830 <mysqld_get_one_option+0x60>
  796dea:	lea    0x1685dcf(%rip),%rax        # 1e1cbc0 <log_error_dest>
  796df1:	lea    0xd95af8(%rip),%rsi        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  796df8:	mov    %rsi,(%rax)
  796dfb:	xor    %eax,%eax
  796dfd:	jmpq   796838 <mysqld_get_one_option+0x68>
  796e02:	lea    0x16866d7(%rip),%rax        # 1e1d4e0 <test_flags>
  796e09:	orl    $0x100,(%rax)
  796e0f:	xor    %eax,%eax
  796e11:	jmpq   796838 <mysqld_get_one_option+0x68>
  796e16:	lea    0x15d7eb3(%rip),%rax        # 1d6ecd0 <opt_use_ssl>
  796e1d:	movb   $0x1,(%rax)
  796e20:	lea    0x16832d9(%rip),%rax        # 1e1a100 <opt_ssl_crl>
  796e27:	movq   $0x0,(%rax)
  796e2e:	lea    0x16832bb(%rip),%rax        # 1e1a0f0 <opt_ssl_crlpath>
  796e35:	movq   $0x0,(%rax)
  796e3c:	xor    %eax,%eax
  796e3e:	jmpq   796838 <mysqld_get_one_option+0x68>
  796e43:	lea    0x1686696(%rip),%rax        # 1e1d4e0 <test_flags>
  796e4a:	orl    $0x200,(%rax)
  796e50:	xor    %eax,%eax
  796e52:	jmpq   796838 <mysqld_get_one_option+0x68>
  796e57:	lea    0x16868f2(%rip),%rax        # 1e1d750 <opt_skip_name_resolve>
  796e5e:	orq    $0x40,0x1686a9a(%rip)        # 1e1d900 <_ZL15opt_specialflag>
  796e66:	movb   $0x1,(%rax)
  796e69:	xor    %eax,%eax
  796e6b:	jmpq   796838 <mysqld_get_one_option+0x68>
  796e70:	lea    0x1686449(%rip),%rax        # 1e1d2c0 <host_cache_size_specified>
  796e77:	movb   $0x1,(%rax)
  796e7a:	xor    %eax,%eax
  796e7c:	jmpq   796838 <mysqld_get_one_option+0x68>
  796e81:	lea    0x1686448(%rip),%rax        # 1e1d2d0 <thread_cache_size_specified>
  796e88:	movb   $0x1,(%rax)
  796e8b:	xor    %eax,%eax
  796e8d:	jmpq   796838 <mysqld_get_one_option+0x68>
  796e92:	lea    0xb7e54d(%rip),%rsi        # 13153e6 <_IO_stdin_used+0x1a6>
  796e99:	xor    %edi,%edi
  796e9b:	callq  c5ef90 <_Z35push_deprecated_warn_no_replacementP3THDPKc>
  796ea0:	lea    0x1686739(%rip),%rax        # 1e1d5e0 <opt_secure_auth>
  796ea7:	cmpb   $0x0,(%rax)
  796eaa:	jne    796830 <mysqld_get_one_option+0x60>
  796eb0:	lea    0xb82521(%rip),%rdi        # 13193d8 <log_10+0xbf8>
  796eb7:	xor    %eax,%eax
  796eb9:	callq  be5b90 <_Z15sql_print_errorPKcz>
  796ebe:	mov    $0x1,%eax
  796ec3:	jmpq   796838 <mysqld_get_one_option+0x68>
  796ec8:	test   %rdx,%rdx
  796ecb:	movb   $0x0,-0xb0(%rbp)
  796ed2:	lea    -0xb0(%rbp),%r13
  796ed9:	je     79702d <mysqld_get_one_option+0x85d>
  796edf:	mov    $0x80,%edx
  796ee4:	mov    %rbx,%rsi
  796ee7:	mov    %r13,%rdi
  796eea:	callq  761e90 <strncpy@plt>
  796eef:	mov    $0x3d,%esi
  796ef4:	mov    %rbx,%rdi
  796ef7:	callq  7625a0 <strchr@plt>
  796efc:	test   %rax,%rax
  796eff:	je     79702d <mysqld_get_one_option+0x85d>
  796f05:	cmpb   $0x0,0x1(%rax)
  796f09:	je     79702d <mysqld_get_one_option+0x85d>
  796f0f:	movzbl (%rbx),%edx
  796f12:	xor    %r14d,%r14d
  796f15:	test   %dl,%dl
  796f17:	je     79709a <mysqld_get_one_option+0x8ca>
  796f1d:	lea    0x161923c(%rip),%rcx        # 1db0160 <my_charset_latin1>
  796f24:	xor    %r14d,%r14d
  796f27:	mov    0x30(%rcx),%r8
  796f2b:	jmp    796f57 <mysqld_get_one_option+0x787>
  796f2d:	nopl   (%rax)
  796f30:	cmp    $0x27,%dl
  796f33:	jne    79709a <mysqld_get_one_option+0x8ca>
  796f39:	test   %r14b,%r14b
  796f3c:	jne    79702d <mysqld_get_one_option+0x85d>
  796f42:	mov    $0x1,%r14d
  796f48:	add    $0x1,%rbx
  796f4c:	movzbl (%rbx),%edx
  796f4f:	test   %dl,%dl
  796f51:	je     79709a <mysqld_get_one_option+0x8ca>
  796f57:	movzbl %dl,%ecx
  796f5a:	testb  $0x8,0x1(%r8,%rcx,1)
  796f60:	je     796f30 <mysqld_get_one_option+0x760>
  796f62:	cmp    $0x27,%dl
  796f65:	jne    796f48 <mysqld_get_one_option+0x778>
  796f67:	jmp    796f39 <mysqld_get_one_option+0x769>
  796f69:	nopl   0x0(%rax)
  796f70:	lea    0xb7e47d(%rip),%rsi        # 13153f4 <_IO_stdin_used+0x1b4>
  796f77:	xor    %edi,%edi
  796f79:	callq  c5ef90 <_Z35push_deprecated_warn_no_replacementP3THDPKc>
  796f7e:	xor    %eax,%eax
  796f80:	jmpq   796838 <mysqld_get_one_option+0x68>
  796f85:	lea    0x1686324(%rip),%rax        # 1e1d2b0 <table_definition_cache_specified>
  796f8c:	movb   $0x1,(%rax)
  796f8f:	xor    %eax,%eax
  796f91:	jmpq   796838 <mysqld_get_one_option+0x68>
  796f96:	lea    0x1684a03(%rip),%rax        # 1e1b9a0 <rpl_filter>
  796f9d:	mov    %rdx,%rsi
  796fa0:	mov    (%rax),%rdi
  796fa3:	callq  e5cbf0 <_ZN10Rpl_filter9add_do_dbEPKc>
  796fa8:	xor    %eax,%eax
  796faa:	jmpq   796838 <mysqld_get_one_option+0x68>
  796faf:	lea    0xb7e3f1(%rip),%rdx        # 13153a7 <_IO_stdin_used+0x167>
  796fb6:	lea    0xb7e402(%rip),%rsi        # 13153bf <_IO_stdin_used+0x17f>
  796fbd:	xor    %edi,%edi
  796fbf:	callq  c5ef20 <_Z20push_deprecated_warnP3THDPKcS2_>
  796fc4:	test   %rbx,%rbx
  796fc7:	je     797198 <mysqld_get_one_option+0x9c8>
  796fcd:	lea    0x15fe4ec(%rip),%rax        # 1d954c0 <disabled_my_option>
  796fd4:	cmp    (%rax),%rbx
  796fd7:	je     797089 <mysqld_get_one_option+0x8b9>
  796fdd:	mov    $0xa,%edx
  796fe2:	xor    %esi,%esi
  796fe4:	mov    %rbx,%rdi
  796fe7:	callq  762dc0 <strtol@plt>
  796fec:	lea    0x15d7d3d(%rip),%rcx        # 1d6ed30 <log_error_verbosity>
  796ff3:	lea    0x1(%rax),%edx
  796ff6:	movslq %edx,%rdx
  796ff9:	mov    $0x3,%eax
  796ffe:	cmp    $0x3,%rdx
  797002:	cmovb  %rdx,%rax
  797006:	mov    %rax,(%rcx)
  797009:	xor    %eax,%eax
  79700b:	jmpq   796838 <mysqld_get_one_option+0x68>
  797010:	movb   $0x0,(%rax)
  797013:	cmpb   $0x0,(%r12)
  797018:	je     79702d <mysqld_get_one_option+0x85d>
  79701a:	mov    %r12,%rsi
  79701d:	mov    %rbx,%rdi
  797020:	callq  effcc0 <_Z22add_pfs_instr_to_arrayPKcS0_>
  797025:	test   %eax,%eax
  797027:	je     796830 <mysqld_get_one_option+0x60>
  79702d:	lea    0xb82514(%rip),%rdi        # 1319548 <log_10+0xd68>
  797034:	xor    %eax,%eax
  797036:	mov    %r13,%rsi
  797039:	callq  be8180 <_Z17sql_print_warningPKcz>
  79703e:	xor    %eax,%eax
  797040:	jmpq   796838 <mysqld_get_one_option+0x68>
  797045:	callq  cd9c60 <_Z20ignore_db_dirs_resetv>
  79704a:	xor    %eax,%eax
  79704c:	nopl   0x0(%rax)
  797050:	jmpq   796838 <mysqld_get_one_option+0x68>
  797055:	lea    0x1684944(%rip),%rax        # 1e1b9a0 <rpl_filter>
  79705c:	mov    %rbx,%rsi
  79705f:	mov    (%rax),%rdi
  797062:	callq  e5cd00 <_ZN10Rpl_filter14add_db_rewriteEPKcS1_>
  797067:	xor    %eax,%eax
  797069:	jmpq   796838 <mysqld_get_one_option+0x68>
  79706e:	lea    0xb821db(%rip),%rdi        # 1319250 <log_10+0xa70>
  797075:	xor    %eax,%eax
  797077:	mov    %r12,%rdx
  79707a:	mov    %rbx,%rsi
  79707d:	callq  be8180 <_Z17sql_print_warningPKcz>
  797082:	xor    %eax,%eax
  797084:	jmpq   796838 <mysqld_get_one_option+0x68>
  797089:	mov    $0x1,%eax
  79708e:	lea    0x15d7c9b(%rip),%rcx        # 1d6ed30 <log_error_verbosity>
  797095:	jmpq   797006 <mysqld_get_one_option+0x836>
  79709a:	cmp    %rbx,%rax
  79709d:	jbe    7971e3 <mysqld_get_one_option+0xa13>
  7970a3:	lea    0x16190b6(%rip),%rdx        # 1db0160 <my_charset_latin1>
  7970aa:	movzbl -0x1(%rax),%ecx
  7970ae:	mov    0x30(%rdx),%rdi
  7970b2:	mov    %rax,%rdx
  7970b5:	movzbl %cl,%esi
  7970b8:	testb  $0x8,0x1(%rdi,%rsi,1)
  7970bd:	jne    7970da <mysqld_get_one_option+0x90a>
  7970bf:	jmpq   7971ab <mysqld_get_one_option+0x9db>
  7970c4:	nopl   0x0(%rax)
  7970c8:	movzbl -0x1(%rdx),%ecx
  7970cc:	movzbl %cl,%esi
  7970cf:	testb  $0x8,0x1(%rdi,%rsi,1)
  7970d4:	je     7971ab <mysqld_get_one_option+0x9db>
  7970da:	sub    $0x1,%rdx
  7970de:	cmp    %rbx,%rdx
  7970e1:	jne    7970c8 <mysqld_get_one_option+0x8f8>
  7970e3:	movb   $0x0,(%rdx)
  7970e6:	cmpb   $0x0,(%rbx)
  7970e9:	je     79702d <mysqld_get_one_option+0x85d>
  7970ef:	lea    0x1(%rax),%r12
  7970f3:	movzbl 0x1(%rax),%eax
  7970f7:	test   %al,%al
  7970f9:	je     797124 <mysqld_get_one_option+0x954>
  7970fb:	lea    0x161905e(%rip),%rdx        # 1db0160 <my_charset_latin1>
  797102:	mov    0x30(%rdx),%rdx
  797106:	jmp    79711d <mysqld_get_one_option+0x94d>
  797108:	nopl   0x0(%rax,%rax,1)
  797110:	add    $0x1,%r12
  797114:	movzbl (%r12),%eax
  797119:	test   %al,%al
  79711b:	je     797124 <mysqld_get_one_option+0x954>
  79711d:	testb  $0x8,0x1(%rdx,%rax,1)
  797122:	jne    797110 <mysqld_get_one_option+0x940>
  797124:	mov    %r12,%rdi
  797127:	callq  762340 <strlen@plt>
  79712c:	add    %r12,%rax
  79712f:	cmp    %r12,%rax
  797132:	jbe    797010 <mysqld_get_one_option+0x840>
  797138:	lea    0x1619021(%rip),%rdx        # 1db0160 <my_charset_latin1>
  79713f:	mov    0x30(%rdx),%rsi
  797143:	jmp    79716a <mysqld_get_one_option+0x99a>
  797145:	nopl   (%rax)
  797148:	cmp    $0x27,%dl
  79714b:	jne    797010 <mysqld_get_one_option+0x840>
  797151:	test   %r14b,%r14b
  797154:	je     79702d <mysqld_get_one_option+0x85d>
  79715a:	xor    %r14d,%r14d
  79715d:	sub    $0x1,%rax
  797161:	cmp    %r12,%rax
  797164:	je     797010 <mysqld_get_one_option+0x840>
  79716a:	movzbl -0x1(%rax),%edx
  79716e:	movzbl %dl,%ecx
  797171:	testb  $0x8,0x1(%rsi,%rcx,1)
  797176:	je     797148 <mysqld_get_one_option+0x978>
  797178:	cmp    $0x27,%dl
  79717b:	jne    79715d <mysqld_get_one_option+0x98d>
  79717d:	jmp    797151 <mysqld_get_one_option+0x981>
  79717f:	nop
  797180:	lea    0xb82161(%rip),%rdi        # 13192e8 <log_10+0xb08>
  797187:	xor    %eax,%eax
  797189:	callq  be5b90 <_Z15sql_print_errorPKcz>
  79718e:	mov    $0x1,%eax
  797193:	jmpq   796838 <mysqld_get_one_option+0x68>
  797198:	lea    0x15d7b91(%rip),%rcx        # 1d6ed30 <log_error_verbosity>
  79719f:	mov    (%rcx),%rax
  7971a2:	lea    0x1(%rax),%rdx
  7971a6:	jmpq   796ff9 <mysqld_get_one_option+0x829>
  7971ab:	cmp    $0x2f,%cl
  7971ae:	movb   $0x0,(%rdx)
  7971b1:	jne    7970e6 <mysqld_get_one_option+0x916>
  7971b7:	movb   $0x0,-0x1(%rdx)
  7971bb:	jmpq   7970e6 <mysqld_get_one_option+0x916>
  7971c0:	lea    0xb820e9(%rip),%rdi        # 13192b0 <log_10+0xad0>
  7971c7:	callq  be5b90 <_Z15sql_print_errorPKcz>
  7971cc:	mov    $0x1,%eax
  7971d1:	jmpq   796838 <mysqld_get_one_option+0x68>
  7971d6:	mov    %rax,%rcx
  7971d9:	jmpq   796c9c <mysqld_get_one_option+0x4cc>
  7971de:	callq  762130 <__stack_chk_fail@plt>
  7971e3:	mov    %rax,%rdx
  7971e6:	jmpq   7970e3 <mysqld_get_one_option+0x913>
  7971eb:	nopl   0x0(%rax,%rax,1)
