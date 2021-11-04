// TC_OUT
0000000000e75850 <_Z25slave_start_single_workerP14Relay_log_infom>:
  e75850:	push   %rbp
  e75851:	xor    %ecx,%ecx
  e75853:	mov    %rsp,%rbp
  e75856:	push   %r15
  e75858:	push   %r14
  e7585a:	push   %r13
  e7585c:	mov    %rsi,%r13
  e7585f:	push   %r12
  e75861:	push   %rbx
  e75862:	mov    %rdi,%rbx
  e75865:	mov    %rbx,%rdx
  e75868:	sub    $0x68,%rsp
  e7586c:	lea    0xfbe91d(%rip),%rax        # 1e34190 <opt_rli_repository_id>
  e75873:	mov    (%rax),%rdi
  e75876:	callq  e894e0 <_ZN16Rpl_info_factory13create_workerEjjP14Relay_log_infob>
  e7587b:	test   %rax,%rax
  e7587e:	mov    %rax,%r12
  e75881:	je     e75b40 <_Z25slave_start_single_workerP14Relay_log_infom+0x2f0>
  e75887:	mov    %r13,%rdx
  e7588a:	mov    %rbx,%rsi
  e7588d:	mov    %rax,%rdi
  e75890:	callq  e8ba20 <_ZN12Slave_worker11init_workerEP14Relay_log_infom>
  e75895:	test   %eax,%eax
  e75897:	jne    e759f8 <_Z25slave_start_single_workerP14Relay_log_infom+0x1a8>
  e7589d:	mov    0x2db0(%rbx),%rsi
  e758a4:	cmp    %rsi,%r13
  e758a7:	jae    e75a20 <_Z25slave_start_single_workerP14Relay_log_infom+0x1d0>
  e758ad:	mov    0x2de0(%rbx),%rax
  e758b4:	lea    -0x250b(%rip),%rcx        # e733b0 <handle_slave_worker>
  e758bb:	lea    -0x80(%rbp),%rsi
  e758bf:	lea    0xfa4e9a(%rip),%rdx        # 1e1a760 <connection_attrib>
  e758c6:	mov    %r12,%r8
  e758c9:	mov    %r12,(%rax,%r13,8)
  e758cd:	mov    0xfd9a11(%rip),%edi        # 1e4f2e4 <_ZL23key_thread_slave_worker>
  e758d3:	movl   $0x0,0x838(%r12)
  e758df:	callq  ed6dd0 <pfs_spawn_thread_v1>
  e758e4:	test   %eax,%eax
  e758e6:	mov    %eax,%r14d
  e758e9:	jne    e759a0 <_Z25slave_start_single_workerP14Relay_log_infom+0x150>
  e758ef:	mov    0x3390(%r12),%rsi
  e758f7:	test   %rsi,%rsi
  e758fa:	je     e75d78 <_Z25slave_start_single_workerP14Relay_log_infom+0x528>
  e75900:	lea    -0x70(%rbp),%rdi
  e75904:	lea    0x748f2d(%rip),%rcx        # 15be838 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x6a4>
  e7590b:	lea    0x3368(%r12),%r13
  e75913:	xor    %edx,%edx
  e75915:	mov    $0x1a69,%r8d
  e7591b:	callq  ed78e0 <pfs_start_mutex_wait_v1>
  e75920:	mov    %r13,%rdi
  e75923:	mov    %rax,%r15
  e75926:	callq  7620e0 <pthread_mutex_lock@plt>
  e7592b:	test   %r15,%r15
  e7592e:	je     e7593a <_Z25slave_start_single_workerP14Relay_log_infom+0xea>
  e75930:	mov    %eax,%esi
  e75932:	mov    %r15,%rdi
  e75935:	callq  ed8be0 <pfs_end_mutex_wait_v1>
  e7593a:	mov    0x38f0(%r12),%eax
  e75942:	test   %eax,%eax
  e75944:	je     e75bc0 <_Z25slave_start_single_workerP14Relay_log_infom+0x370>
  e7594a:	mov    0x3390(%r12),%rdi
  e75952:	test   %rdi,%rdi
  e75955:	je     e7595c <_Z25slave_start_single_workerP14Relay_log_infom+0x10c>
  e75957:	callq  ed6140 <pfs_unlock_mutex_v1>
  e7595c:	mov    %r13,%rdi
  e7595f:	callq  762030 <pthread_mutex_unlock@plt>
  e75964:	mov    0x31f8(%rbx),%rdx
  e7596b:	cmp    0x3200(%rbx),%rdx
  e75972:	mov    0x3350(%r12),%r12
  e7597a:	je     e75c20 <_Z25slave_start_single_workerP14Relay_log_infom+0x3d0>
  e75980:	mov    0x3288(%rbx),%rax
  e75987:	lea    (%rax,%rdx,8),%rax
  e7598b:	lea    0x1(%rdx),%rcx
  e7598f:	test   %rax,%rax
  e75992:	mov    %rcx,0x31f8(%rbx)
  e75999:	je     e759e3 <_Z25slave_start_single_workerP14Relay_log_infom+0x193>
  e7599b:	mov    %r12,(%rax)
  e7599e:	jmp    e759e3 <_Z25slave_start_single_workerP14Relay_log_infom+0x193>
  e759a0:	mov    (%rbx),%rax
  e759a3:	xor    %esi,%esi
  e759a5:	mov    %rbx,%rdi
  e759a8:	callq  *0x8(%rax)
  e759ab:	lea    0x74b22e(%rip),%rdi        # 15c0be0 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x2a4c>
  e759b2:	mov    %rax,%rsi
  e759b5:	mov    %r14d,%edx
  e759b8:	xor    %eax,%eax
  e759ba:	callq  be5b90 <_Z15sql_print_errorPKcz>
  e759bf:	mov    (%r12),%rax
  e759c3:	mov    %r12,%rdi
  e759c6:	callq  *0x18(%rax)
  e759c9:	mov    0x2db0(%rbx),%rax
  e759d0:	lea    0x1(%r13),%rdx
  e759d4:	cmp    %rdx,%rax
  e759d7:	je     e75b70 <_Z25slave_start_single_workerP14Relay_log_infom+0x320>
  e759dd:	mov    $0x1,%r14d
  e759e3:	add    $0x68,%rsp
  e759e7:	mov    %r14d,%eax
  e759ea:	pop    %rbx
  e759eb:	pop    %r12
  e759ed:	pop    %r13
  e759ef:	pop    %r14
  e759f1:	pop    %r15
  e759f3:	pop    %rbp
  e759f4:	retq   
  e759f5:	nopl   (%rax)
  e759f8:	mov    (%rbx),%rax
  e759fb:	xor    %esi,%esi
  e759fd:	mov    %rbx,%rdi
  e75a00:	callq  *0x8(%rax)
  e75a03:	lea    0x74b1a6(%rip),%rdi        # 15c0bb0 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x2a1c>
  e75a0a:	mov    %rax,%rsi
  e75a0d:	xor    %eax,%eax
  e75a0f:	callq  be5b90 <_Z15sql_print_errorPKcz>
  e75a14:	jmp    e759bf <_Z25slave_start_single_workerP14Relay_log_infom+0x16f>
  e75a16:	nopw   %cs:0x0(%rax,%rax,1)
  e75a20:	lea    0x1(%r13),%r15
  e75a24:	cmp    %r15,%rsi
  e75a27:	je     e758ad <_Z25slave_start_single_workerP14Relay_log_infom+0x5d>
  e75a2d:	nopl   (%rax)
  e75a30:	jae    e75cd0 <_Z25slave_start_single_workerP14Relay_log_infom+0x480>
  e75a36:	cmp    0x2db8(%rbx),%r15
  e75a3d:	ja     e75ce0 <_Z25slave_start_single_workerP14Relay_log_infom+0x490>
  e75a43:	lea    0x2dc0(%rbx),%rax
  e75a4a:	mov    %rax,-0x88(%rbp)
  e75a51:	cmp    %rsi,%r15
  e75a54:	je     e758ad <_Z25slave_start_single_workerP14Relay_log_infom+0x5d>
  e75a5a:	cmp    %rsi,0x2db8(%rbx)
  e75a61:	je     e75aa1 <_Z25slave_start_single_workerP14Relay_log_infom+0x251>
  e75a63:	mov    0x2de0(%rbx),%rax
  e75a6a:	lea    (%rax,%rsi,8),%rax
  e75a6e:	lea    0x1(%rsi),%rdx
  e75a72:	test   %rax,%rax
  e75a75:	mov    %rdx,0x2db0(%rbx)
  e75a7c:	mov    %rdx,%rsi
  e75a7f:	je     e75a51 <_Z25slave_start_single_workerP14Relay_log_infom+0x201>
  e75a81:	movq   $0x0,(%rax)
  e75a88:	mov    0x2db0(%rbx),%rsi
  e75a8f:	cmp    %rsi,%r15
  e75a92:	je     e758ad <_Z25slave_start_single_workerP14Relay_log_infom+0x5d>
  e75a98:	cmp    %rsi,0x2db8(%rbx)
  e75a9f:	jne    e75a63 <_Z25slave_start_single_workerP14Relay_log_infom+0x213>
  e75aa1:	lea    (%rsi,%rsi,1),%r14
  e75aa5:	cmp    %r14,%rsi
  e75aa8:	jae    e75a63 <_Z25slave_start_single_workerP14Relay_log_infom+0x213>
  e75aaa:	mov    0x2de8(%rbx),%edi
  e75ab0:	shl    $0x4,%rsi
  e75ab4:	mov    $0x10,%edx
  e75ab9:	callq  eb5ec0 <my_malloc>
  e75abe:	test   %rax,%rax
  e75ac1:	mov    0x2db0(%rbx),%rsi
  e75ac8:	je     e75a51 <_Z25slave_start_single_workerP14Relay_log_infom+0x201>
  e75aca:	xor    %edx,%edx
  e75acc:	test   %rsi,%rsi
  e75acf:	mov    0x2de0(%rbx),%rdi
  e75ad6:	mov    %rax,%rcx
  e75ad9:	je     e75b0a <_Z25slave_start_single_workerP14Relay_log_infom+0x2ba>
  e75adb:	nopl   0x0(%rax,%rax,1)
  e75ae0:	test   %rcx,%rcx
  e75ae3:	lea    (%rdi,%rdx,8),%r9
  e75ae7:	je     e75afd <_Z25slave_start_single_workerP14Relay_log_infom+0x2ad>
  e75ae9:	mov    (%r9),%rsi
  e75aec:	mov    %rsi,(%rcx)
  e75aef:	mov    0x2de0(%rbx),%rdi
  e75af6:	mov    0x2db0(%rbx),%rsi
  e75afd:	add    $0x1,%rdx
  e75b01:	add    $0x8,%rcx
  e75b05:	cmp    %rsi,%rdx
  e75b08:	jb     e75ae0 <_Z25slave_start_single_workerP14Relay_log_infom+0x290>
  e75b0a:	cmp    -0x88(%rbp),%rdi
  e75b11:	je     e75b2d <_Z25slave_start_single_workerP14Relay_log_infom+0x2dd>
  e75b13:	mov    %rax,-0x90(%rbp)
  e75b1a:	callq  eb6000 <my_free>
  e75b1f:	mov    0x2db0(%rbx),%rsi
  e75b26:	mov    -0x90(%rbp),%rax
  e75b2d:	mov    %rax,0x2de0(%rbx)
  e75b34:	mov    %r14,0x2db8(%rbx)
  e75b3b:	jmpq   e75a6a <_Z25slave_start_single_workerP14Relay_log_infom+0x21a>
  e75b40:	mov    (%rbx),%rax
  e75b43:	xor    %esi,%esi
  e75b45:	mov    %rbx,%rdi
  e75b48:	mov    $0x1,%r14d
  e75b4e:	callq  *0x8(%rax)
  e75b51:	lea    0x74b058(%rip),%rdi        # 15c0bb0 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x2a1c>
  e75b58:	mov    %rax,%rsi
  e75b5b:	xor    %eax,%eax
  e75b5d:	callq  be5b90 <_Z15sql_print_errorPKcz>
  e75b62:	jmpq   e759e3 <_Z25slave_start_single_workerP14Relay_log_infom+0x193>
  e75b67:	nopw   0x0(%rax,%rax,1)
  e75b70:	mov    0x2de0(%rbx),%rdx
  e75b77:	lea    (%rdx,%r13,8),%rdi
  e75b7b:	lea    (%rdx,%rax,8),%rdx
  e75b7f:	lea    0x8(%rdi),%rsi
  e75b83:	cmp    %rdx,%rsi
  e75b86:	je     e75ba4 <_Z25slave_start_single_workerP14Relay_log_infom+0x354>
  e75b88:	sub    %rsi,%rdx
  e75b8b:	sar    $0x3,%rdx
  e75b8f:	test   %rdx,%rdx
  e75b92:	je     e75ba4 <_Z25slave_start_single_workerP14Relay_log_infom+0x354>
  e75b94:	shl    $0x3,%rdx
  e75b98:	callq  761ec0 <memmove@plt>
  e75b9d:	mov    0x2db0(%rbx),%rax
  e75ba4:	sub    $0x1,%rax
  e75ba8:	mov    $0x1,%r14d
  e75bae:	mov    %rax,0x2db0(%rbx)
  e75bb5:	jmpq   e759e3 <_Z25slave_start_single_workerP14Relay_log_infom+0x193>
  e75bba:	nopw   0x0(%rax,%rax,1)
  e75bc0:	mov    0x33c8(%r12),%rsi
  e75bc8:	test   %rsi,%rsi
  e75bcb:	je     e75d8d <_Z25slave_start_single_workerP14Relay_log_infom+0x53d>
  e75bd1:	mov    0x3390(%r12),%rdx
  e75bd9:	lea    -0x70(%rbp),%rdi
  e75bdd:	lea    0x748c54(%rip),%r8        # 15be838 <_ZN13Binlog_sender15PACKET_MIN_SIZEE+0x6a4>
  e75be4:	xor    %ecx,%ecx
  e75be6:	mov    $0x1a6b,%r9d
  e75bec:	callq  ed7ac0 <pfs_start_cond_wait_v1>
  e75bf1:	lea    0x3398(%r12),%rdi
  e75bf9:	mov    %rax,%r15
  e75bfc:	mov    %r13,%rsi
  e75bff:	callq  762590 <pthread_cond_wait@plt>
  e75c04:	test   %r15,%r15
  e75c07:	je     e7594a <_Z25slave_start_single_workerP14Relay_log_infom+0xfa>
  e75c0d:	mov    %eax,%esi
  e75c0f:	mov    %r15,%rdi
  e75c12:	callq  ed90b0 <pfs_end_cond_wait_v1>
  e75c17:	jmpq   e7594a <_Z25slave_start_single_workerP14Relay_log_infom+0xfa>
  e75c1c:	nopl   0x0(%rax)
  e75c20:	lea    (%rdx,%rdx,1),%r13
  e75c24:	cmp    %r13,%rdx
  e75c27:	jae    e75980 <_Z25slave_start_single_workerP14Relay_log_infom+0x130>
  e75c2d:	mov    0x3290(%rbx),%edi
  e75c33:	shl    $0x4,%rdx
  e75c37:	mov    %rdx,%rsi
  e75c3a:	mov    $0x10,%edx
  e75c3f:	callq  eb5ec0 <my_malloc>
  e75c44:	test   %rax,%rax
  e75c47:	mov    %rax,%r15
  e75c4a:	je     e759e3 <_Z25slave_start_single_workerP14Relay_log_infom+0x193>
  e75c50:	mov    0x31f8(%rbx),%rdx
  e75c57:	xor    %ecx,%ecx
  e75c59:	mov    0x3288(%rbx),%rdi
  e75c60:	mov    %rax,%rsi
  e75c63:	test   %rdx,%rdx
  e75c66:	je     e75c9a <_Z25slave_start_single_workerP14Relay_log_infom+0x44a>
  e75c68:	nopl   0x0(%rax,%rax,1)
  e75c70:	test   %rsi,%rsi
  e75c73:	lea    (%rdi,%rcx,8),%r8
  e75c77:	je     e75c8d <_Z25slave_start_single_workerP14Relay_log_infom+0x43d>
  e75c79:	mov    (%r8),%rdx
  e75c7c:	mov    %rdx,(%rsi)
  e75c7f:	mov    0x3288(%rbx),%rdi
  e75c86:	mov    0x31f8(%rbx),%rdx
  e75c8d:	add    $0x1,%rcx
  e75c91:	add    $0x8,%rsi
  e75c95:	cmp    %rdx,%rcx
  e75c98:	jb     e75c70 <_Z25slave_start_single_workerP14Relay_log_infom+0x420>
  e75c9a:	lea    0x3208(%rbx),%rax
  e75ca1:	cmp    %rax,%rdi
  e75ca4:	je     e75cb2 <_Z25slave_start_single_workerP14Relay_log_infom+0x462>
  e75ca6:	callq  eb6000 <my_free>
  e75cab:	mov    0x31f8(%rbx),%rdx
  e75cb2:	mov    %r15,0x3288(%rbx)
  e75cb9:	mov    %r13,0x3200(%rbx)
  e75cc0:	mov    %r15,%rax
  e75cc3:	jmpq   e75987 <_Z25slave_start_single_workerP14Relay_log_infom+0x137>
  e75cc8:	nopl   0x0(%rax,%rax,1)
  e75cd0:	mov    %r15,0x2db0(%rbx)
  e75cd7:	jmpq   e758ad <_Z25slave_start_single_workerP14Relay_log_infom+0x5d>
  e75cdc:	nopl   0x0(%rax)
  e75ce0:	mov    0x2de8(%rbx),%edi
  e75ce6:	lea    0x0(,%r15,8),%rsi
  e75cee:	mov    $0x10,%edx
  e75cf3:	callq  eb5ec0 <my_malloc>
  e75cf8:	test   %rax,%rax
  e75cfb:	mov    %rax,%r14
  e75cfe:	je     e758ad <_Z25slave_start_single_workerP14Relay_log_infom+0x5d>
  e75d04:	mov    0x2db0(%rbx),%rsi
  e75d0b:	xor    %edx,%edx
  e75d0d:	mov    0x2de0(%rbx),%rdi
  e75d14:	mov    %rax,%rcx
  e75d17:	test   %rsi,%rsi
  e75d1a:	je     e75d4a <_Z25slave_start_single_workerP14Relay_log_infom+0x4fa>
  e75d1c:	nopl   0x0(%rax)
  e75d20:	test   %rcx,%rcx
  e75d23:	lea    (%rdi,%rdx,8),%r8
  e75d27:	je     e75d3d <_Z25slave_start_single_workerP14Relay_log_infom+0x4ed>
  e75d29:	mov    (%r8),%rsi
  e75d2c:	mov    %rsi,(%rcx)
  e75d2f:	mov    0x2de0(%rbx),%rdi
  e75d36:	mov    0x2db0(%rbx),%rsi
  e75d3d:	add    $0x1,%rdx
  e75d41:	add    $0x8,%rcx
  e75d45:	cmp    %rsi,%rdx
  e75d48:	jb     e75d20 <_Z25slave_start_single_workerP14Relay_log_infom+0x4d0>
  e75d4a:	lea    0x2dc0(%rbx),%rax
  e75d51:	cmp    %rax,%rdi
  e75d54:	je     e75d62 <_Z25slave_start_single_workerP14Relay_log_infom+0x512>
  e75d56:	callq  eb6000 <my_free>
  e75d5b:	mov    0x2db0(%rbx),%rsi
  e75d62:	mov    %r14,0x2de0(%rbx)
  e75d69:	mov    %r15,0x2db8(%rbx)
  e75d70:	jmpq   e75a43 <_Z25slave_start_single_workerP14Relay_log_infom+0x1f3>
  e75d75:	nopl   (%rax)
  e75d78:	lea    0x3368(%r12),%r13
  e75d80:	mov    %r13,%rdi
  e75d83:	callq  7620e0 <pthread_mutex_lock@plt>
  e75d88:	jmpq   e7593a <_Z25slave_start_single_workerP14Relay_log_infom+0xea>
  e75d8d:	lea    0x3398(%r12),%rdi
  e75d95:	mov    %r13,%rsi
  e75d98:	callq  762590 <pthread_cond_wait@plt>
  e75d9d:	jmpq   e7594a <_Z25slave_start_single_workerP14Relay_log_infom+0xfa>
  e75da2:	data32 data32 data32 data32 nopw %cs:0x0(%rax,%rax,1)
