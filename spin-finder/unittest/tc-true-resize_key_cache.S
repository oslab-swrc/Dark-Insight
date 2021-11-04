// TC_OUT resize_key_cache,0xea60e0,0xea614c,0x38(%rbx)
// TC_OUT resize_key_cache,0xea61b0,0xea621c,0x38(%rbx)
0000000000ea6000 <resize_key_cache>:
  ea6000:	push   %rbp
  ea6001:	mov    %rsp,%rbp
  ea6004:	push   %r15
  ea6006:	push   %r14
  ea6008:	push   %r13
  ea600a:	mov    %rdi,%r13
  ea600d:	push   %r12
  ea600f:	push   %rbx
  ea6010:	sub    $0x78,%rsp
  ea6014:	cmpb   $0x0,(%rdi)
  ea6017:	mov    %rdx,-0x80(%rbp)
  ea601b:	mov    %rcx,-0x88(%rbp)
  ea6022:	mov    %r8,-0x90(%rbp)
  ea6029:	mov    %r9,-0x98(%rbp)
  ea6030:	je     ea63d5 <resize_key_cache+0x3d5>
  ea6036:	mov    0x10(%rdi),%eax
  ea6039:	mov    %rsi,%rbx
  ea603c:	cmp    -0x80(%rbp),%rax
  ea6040:	je     ea62e6 <resize_key_cache+0x2e6>
  ea6046:	mov    0xd8(%r13),%rsi
  ea604d:	test   %rsi,%rsi
  ea6050:	je     ea64ae <resize_key_cache+0x4ae>
  ea6056:	lea    0xeeed83(%rip),%r12        # 1d94de0 <PSI_server>
  ea605d:	lea    0xb0(%r13),%r14
  ea6064:	xor    %edx,%edx
  ea6066:	lea    -0x70(%rbp),%rdi
  ea606a:	mov    $0x1d0,%r8d
  ea6070:	lea    0x71edf1(%rip),%rcx        # 15c4e68 <_ZTS14Rpl_info_table+0x198>
  ea6077:	mov    (%r12),%rax
  ea607b:	callq  *0x190(%rax)
  ea6081:	mov    %r14,%rdi
  ea6084:	mov    %rax,%r15
  ea6087:	callq  7620e0 <pthread_mutex_lock@plt>
  ea608c:	test   %r15,%r15
  ea608f:	je     ea60a0 <resize_key_cache+0xa0>
  ea6091:	mov    (%r12),%rdx
  ea6095:	mov    %eax,%esi
  ea6097:	mov    %r15,%rdi
  ea609a:	callq  *0x198(%rdx)
  ea60a0:	lea    -0x70(%rbp),%rax
  ea60a4:	mov    %rax,-0x78(%rbp)
  ea60a8:	nopl   0x0(%rax,%rax,1)
  ea60b0:	cmpb   $0x0,0x1(%r13)
  ea60b5:	je     ea6159 <resize_key_cache+0x159>
  ea60bb:	mov    0xe0(%r13),%rax
  ea60c2:	test   %rax,%rax
  ea60c5:	je     ea6150 <resize_key_cache+0x150>
  ea60cb:	mov    0x38(%rax),%rdx
  ea60cf:	mov    %rdx,0x38(%rbx)
  ea60d3:	mov    %rbx,0x38(%rax)
  ea60d7:	mov    %rbx,0xe0(%r13)
  ea60de:	jmp    ea6138 <resize_key_cache+0x138>
  ea60e0:	lea    0xeeecf9(%rip),%r12        # 1d94de0 <PSI_server>
  ea60e7:	xor    %ecx,%ecx
  ea60e9:	mov    0xd8(%r13),%rdx
  ea60f0:	mov    $0x30d,%r9d
  ea60f6:	lea    0x71ed6b(%rip),%r8        # 15c4e68 <_ZTS14Rpl_info_table+0x198>
  ea60fd:	mov    -0x78(%rbp),%rdi
  ea6101:	mov    (%r12),%rax
  ea6105:	callq  *0x1c0(%rax)
  ea610b:	mov    %r14,%rsi
  ea610e:	mov    %rax,%r15
  ea6111:	mov    %rbx,%rdi
  ea6114:	callq  762590 <pthread_cond_wait@plt>
  ea6119:	test   %r15,%r15
  ea611c:	je     ea612d <resize_key_cache+0x12d>
  ea611e:	mov    (%r12),%rcx
  ea6122:	mov    %eax,%esi
  ea6124:	mov    %r15,%rdi
  ea6127:	callq  *0x1c8(%rcx)
  ea612d:	cmpq   $0x0,0x38(%rbx)
  ea6132:	je     ea60b0 <resize_key_cache+0xb0>
  ea6138:	mov    0x30(%rbx),%rsi
  ea613c:	test   %rsi,%rsi
  ea613f:	jne    ea60e0 <resize_key_cache+0xe0>
  ea6141:	mov    %r14,%rsi
  ea6144:	mov    %rbx,%rdi
  ea6147:	callq  762590 <pthread_cond_wait@plt>
  ea614c:	jmp    ea612d <resize_key_cache+0x12d>
  ea614e:	xchg   %ax,%ax
  ea6150:	mov    %rbx,0x38(%rbx)
  ea6154:	jmpq   ea60d7 <resize_key_cache+0xd7>
  ea6159:	cmpb   $0x0,0x3(%r13)
  ea615e:	movb   $0x1,0x1(%r13)
  ea6163:	jne    ea63e8 <resize_key_cache+0x3e8>
  ea6169:	lea    -0x70(%rbp),%rax
  ea616d:	mov    %rax,-0x78(%rbp)
  ea6171:	nopl   0x0(%rax)
  ea6178:	cmpq   $0x0,0x60(%r13)
  ea617d:	je     ea6229 <resize_key_cache+0x229>
  ea6183:	mov    0xe8(%r13),%rax
  ea618a:	test   %rax,%rax
  ea618d:	je     ea6220 <resize_key_cache+0x220>
  ea6193:	mov    0x38(%rax),%rdx
  ea6197:	mov    %rdx,0x38(%rbx)
  ea619b:	mov    %rbx,0x38(%rax)
  ea619f:	mov    %rbx,0xe8(%r13)
  ea61a6:	jmp    ea6208 <resize_key_cache+0x208>
  ea61a8:	nopl   0x0(%rax,%rax,1)
  ea61b0:	lea    0xeeec29(%rip),%r12        # 1d94de0 <PSI_server>
  ea61b7:	xor    %ecx,%ecx
  ea61b9:	mov    0xd8(%r13),%rdx
  ea61c0:	mov    $0x30d,%r9d
  ea61c6:	lea    0x71ec9b(%rip),%r8        # 15c4e68 <_ZTS14Rpl_info_table+0x198>
  ea61cd:	mov    -0x78(%rbp),%rdi
  ea61d1:	mov    (%r12),%rax
  ea61d5:	callq  *0x1c0(%rax)
  ea61db:	mov    %r14,%rsi
  ea61de:	mov    %rax,%r15
  ea61e1:	mov    %rbx,%rdi
  ea61e4:	callq  762590 <pthread_cond_wait@plt>
  ea61e9:	test   %r15,%r15
  ea61ec:	je     ea61fd <resize_key_cache+0x1fd>
  ea61ee:	mov    (%r12),%rcx
  ea61f2:	mov    %eax,%esi
  ea61f4:	mov    %r15,%rdi
  ea61f7:	callq  *0x1c8(%rcx)
  ea61fd:	cmpq   $0x0,0x38(%rbx)
  ea6202:	je     ea6178 <resize_key_cache+0x178>
  ea6208:	mov    0x30(%rbx),%rsi
  ea620c:	test   %rsi,%rsi
  ea620f:	jne    ea61b0 <resize_key_cache+0x1b0>
  ea6211:	mov    %r14,%rsi
  ea6214:	mov    %rbx,%rdi
  ea6217:	callq  762590 <pthread_cond_wait@plt>
  ea621c:	jmp    ea61fd <resize_key_cache+0x1fd>
  ea621e:	xchg   %ax,%ax
  ea6220:	mov    %rbx,0x38(%rbx)
  ea6224:	jmpq   ea619f <resize_key_cache+0x19f>
  ea6229:	xor    %esi,%esi
  ea622b:	mov    %r13,%rdi
  ea622e:	callq  ea5f40 <end_key_cache>
  ea6233:	mov    -0x98(%rbp),%r8
  ea623a:	mov    -0x90(%rbp),%rcx
  ea6241:	mov    %r13,%rdi
  ea6244:	mov    -0x88(%rbp),%rdx
  ea624b:	mov    -0x80(%rbp),%rsi
  ea624f:	callq  ea5980 <init_key_cache>
  ea6254:	mov    %eax,%r15d
  ea6257:	mov    0xe0(%r13),%r12
  ea625e:	movb   $0x0,0x1(%r13)
  ea6263:	test   %r12,%r12
  ea6266:	je     ea62b0 <resize_key_cache+0x2b0>
  ea6268:	mov    0x38(%r12),%rbx
  ea626d:	jmp    ea6273 <resize_key_cache+0x273>
  ea626f:	nop
  ea6270:	mov    %rax,%rbx
  ea6273:	mov    0x30(%rbx),%rdi
  ea6277:	test   %rdi,%rdi
  ea627a:	je     ea628c <resize_key_cache+0x28c>
  ea627c:	lea    0xeeeb5d(%rip),%rax        # 1d94de0 <PSI_server>
  ea6283:	mov    (%rax),%rax
  ea6286:	callq  *0x170(%rax)
  ea628c:	mov    %rbx,%rdi
  ea628f:	callq  7629b0 <pthread_cond_signal@plt>
  ea6294:	cmp    %rbx,%r12
  ea6297:	mov    0x38(%rbx),%rax
  ea629b:	movq   $0x0,0x38(%rbx)
  ea62a3:	jne    ea6270 <resize_key_cache+0x270>
  ea62a5:	movq   $0x0,0xe0(%r13)
  ea62b0:	mov    0xd8(%r13),%rdi
  ea62b7:	test   %rdi,%rdi
  ea62ba:	je     ea62cc <resize_key_cache+0x2cc>
  ea62bc:	lea    0xeeeb1d(%rip),%rax        # 1d94de0 <PSI_server>
  ea62c3:	mov    (%rax),%rax
  ea62c6:	callq  *0x160(%rax)
  ea62cc:	mov    %r14,%rdi
  ea62cf:	callq  762030 <pthread_mutex_unlock@plt>
  ea62d4:	add    $0x78,%rsp
  ea62d8:	mov    %r15d,%eax
  ea62db:	pop    %rbx
  ea62dc:	pop    %r12
  ea62de:	pop    %r13
  ea62e0:	pop    %r14
  ea62e2:	pop    %r15
  ea62e4:	pop    %rbp
  ea62e5:	retq   
  ea62e6:	mov    -0x88(%rbp),%rax
  ea62ed:	cmp    %rax,0x8(%rdi)
  ea62f1:	jne    ea6046 <resize_key_cache+0x46>
  ea62f7:	mov    0xd8(%rdi),%rsi
  ea62fe:	test   %rsi,%rsi
  ea6301:	je     ea64d9 <resize_key_cache+0x4d9>
  ea6307:	lea    0xeeead2(%rip),%r12        # 1d94de0 <PSI_server>
  ea630e:	lea    0xb0(%r13),%rbx
  ea6315:	xor    %edx,%edx
  ea6317:	lea    -0x70(%rbp),%rdi
  ea631b:	mov    $0x24f,%r8d
  ea6321:	lea    0x71eb40(%rip),%rcx        # 15c4e68 <_ZTS14Rpl_info_table+0x198>
  ea6328:	mov    (%r12),%rax
  ea632c:	callq  *0x190(%rax)
  ea6332:	mov    %rbx,%rdi
  ea6335:	mov    %rax,%r14
  ea6338:	callq  7620e0 <pthread_mutex_lock@plt>
  ea633d:	test   %r14,%r14
  ea6340:	je     ea6351 <resize_key_cache+0x351>
  ea6342:	mov    (%r12),%rdx
  ea6346:	mov    %eax,%esi
  ea6348:	mov    %r14,%rdi
  ea634b:	callq  *0x198(%rdx)
  ea6351:	cmpq   $0x0,-0x90(%rbp)
  ea6359:	je     ea6384 <resize_key_cache+0x384>
  ea635b:	movslq 0x3c(%r13),%rax
  ea635f:	movabs $0x28f5c28f5c28f5c3,%rdx
  ea6369:	imul   -0x90(%rbp),%rax
  ea6371:	shr    $0x2,%rax
  ea6375:	mul    %rdx
  ea6378:	shr    $0x2,%rdx
  ea637c:	add    $0x1,%rdx
  ea6380:	mov    %rdx,0x18(%r13)
  ea6384:	mov    -0x98(%rbp),%rcx
  ea638b:	test   %rcx,%rcx
  ea638e:	je     ea63b1 <resize_key_cache+0x3b1>
  ea6390:	movslq 0x3c(%r13),%rax
  ea6394:	movabs $0x28f5c28f5c28f5c3,%rdx
  ea639e:	imul   %rcx,%rax
  ea63a2:	shr    $0x2,%rax
  ea63a6:	mul    %rdx
  ea63a9:	shr    $0x2,%rdx
  ea63ad:	mov    %rdx,0x20(%r13)
  ea63b1:	mov    0xd8(%r13),%rdi
  ea63b8:	test   %rdi,%rdi
  ea63bb:	je     ea63cd <resize_key_cache+0x3cd>
  ea63bd:	lea    0xeeea1c(%rip),%rax        # 1d94de0 <PSI_server>
  ea63c4:	mov    (%rax),%rax
  ea63c7:	callq  *0x160(%rax)
  ea63cd:	mov    %rbx,%rdi
  ea63d0:	callq  762030 <pthread_mutex_unlock@plt>
  ea63d5:	mov    0x3c(%r13),%eax
  ea63d9:	add    $0x78,%rsp
  ea63dd:	pop    %rbx
  ea63de:	pop    %r12
  ea63e0:	pop    %r13
  ea63e2:	pop    %r14
  ea63e4:	pop    %r15
  ea63e6:	pop    %rbp
  ea63e7:	retq   
  ea63e8:	xor    %r12d,%r12d
  ea63eb:	xor    %r15d,%r15d
  ea63ee:	movb   $0x1,0x2(%r13)
  ea63f3:	cmp    $0x7f,%r12d
  ea63f7:	mov    %r14,-0x78(%rbp)
  ea63fb:	jbe    ea640e <resize_key_cache+0x40e>
  ea63fd:	xor    %r14d,%r14d
  ea6400:	xor    %r12d,%r12d
  ea6403:	test   %r15d,%r15d
  ea6406:	je     ea644d <resize_key_cache+0x44d>
  ea6408:	xor    %r12d,%r12d
  ea640b:	xor    %r15d,%r15d
  ea640e:	mov    %r12d,%eax
  ea6411:	mov    0x100(%r13,%rax,8),%rax
  ea6419:	test   %rax,%rax
  ea641c:	je     ea6438 <resize_key_cache+0x438>
  ea641e:	mov    0x20(%rax),%rax
  ea6422:	mov    %rbx,%rsi
  ea6425:	mov    %r13,%rdi
  ea6428:	add    $0x1,%r15d
  ea642c:	mov    0x18(%rax),%edx
  ea642f:	callq  ea4610 <flush_key_blocks_int.constprop.9>
  ea6434:	test   %eax,%eax
  ea6436:	jne    ea6498 <resize_key_cache+0x498>
  ea6438:	add    $0x1,%r12d
  ea643c:	cmp    $0x7f,%r12d
  ea6440:	jbe    ea640e <resize_key_cache+0x40e>
  ea6442:	xor    %r14d,%r14d
  ea6445:	xor    %r12d,%r12d
  ea6448:	test   %r15d,%r15d
  ea644b:	jne    ea6408 <resize_key_cache+0x408>
  ea644d:	cmp    $0x7f,%r12d
  ea6451:	jbe    ea645e <resize_key_cache+0x45e>
  ea6453:	test   %r14d,%r14d
  ea6456:	je     ea64c2 <resize_key_cache+0x4c2>
  ea6458:	xor    %r14d,%r14d
  ea645b:	xor    %r12d,%r12d
  ea645e:	mov    %r12d,%eax
  ea6461:	mov    0x500(%r13,%rax,8),%rax
  ea6469:	test   %rax,%rax
  ea646c:	je     ea648c <resize_key_cache+0x48c>
  ea646e:	mov    0x20(%rax),%rax
  ea6472:	mov    %rbx,%rsi
  ea6475:	mov    %r13,%rdi
  ea6478:	add    $0x1,%r15d
  ea647c:	add    $0x1,%r14d
  ea6480:	mov    0x18(%rax),%edx
  ea6483:	callq  ea3060 <flush_key_blocks_int.constprop.10>
  ea6488:	test   %eax,%eax
  ea648a:	jne    ea6498 <resize_key_cache+0x498>
  ea648c:	add    $0x1,%r12d
  ea6490:	cmp    $0x7f,%r12d
  ea6494:	jbe    ea645e <resize_key_cache+0x45e>
  ea6496:	jmp    ea6453 <resize_key_cache+0x453>
  ea6498:	mov    -0x78(%rbp),%r14
  ea649c:	movb   $0x0,0x2(%r13)
  ea64a1:	xor    %r15d,%r15d
  ea64a4:	movb   $0x0,0x3(%r13)
  ea64a9:	jmpq   ea6257 <resize_key_cache+0x257>
  ea64ae:	lea    0xb0(%r13),%r14
  ea64b5:	mov    %r14,%rdi
  ea64b8:	callq  7620e0 <pthread_mutex_lock@plt>
  ea64bd:	jmpq   ea60a0 <resize_key_cache+0xa0>
  ea64c2:	test   %r15d,%r15d
  ea64c5:	jne    ea6408 <resize_key_cache+0x408>
  ea64cb:	mov    -0x78(%rbp),%r14
  ea64cf:	movb   $0x0,0x2(%r13)
  ea64d4:	jmpq   ea6169 <resize_key_cache+0x169>
  ea64d9:	lea    0xb0(%rdi),%rbx
  ea64e0:	mov    %rbx,%rdi
  ea64e3:	callq  7620e0 <pthread_mutex_lock@plt>
  ea64e8:	jmpq   ea6351 <resize_key_cache+0x351>
  ea64ed:	nopl   (%rax)
