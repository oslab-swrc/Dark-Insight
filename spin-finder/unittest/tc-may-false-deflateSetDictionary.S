
0000000000004200 <deflateSetDictionary>:
    4200:	push   %r15
    4202:	push   %r14
    4204:	push   %r13
    4206:	push   %r12
    4208:	push   %rbp
    4209:	push   %rbx
    420a:	mov    %rdi,%rbx
    420d:	sub    $0x18,%rsp
    4211:	test   %rdi,%rdi
    4214:	je     441d <deflateSetDictionary+0x21d>
    421a:	test   %rsi,%rsi
    421d:	mov    %rsi,%r15
    4220:	mov    0x38(%rdi),%r13
    4224:	je     441d <deflateSetDictionary+0x21d>
    422a:	test   %r13,%r13
    422d:	je     441d <deflateSetDictionary+0x21d>
    4233:	mov    0x2c(%r13),%ebp
    4237:	cmp    $0x2,%ebp
    423a:	je     441d <deflateSetDictionary+0x21d>
    4240:	cmp    $0x1,%ebp
    4243:	mov    %edx,%r14d
    4246:	je     4397 <deflateSetDictionary+0x197>
    424c:	mov    0xa4(%r13),%eax
    4253:	test   %eax,%eax
    4255:	jne    441d <deflateSetDictionary+0x21d>
    425b:	mov    0x44(%r13),%eax
    425f:	movl   $0x0,0x2c(%r13)
    4267:	cmp    %eax,%r14d
    426a:	jae    4385 <deflateSetDictionary+0x185>
    4270:	mov    0x8(%rbx),%eax
    4273:	mov    (%rbx),%r12
    4276:	mov    %r14d,0x8(%rbx)
    427a:	mov    %r15,(%rbx)
    427d:	mov    %eax,0xc(%rsp)
    4281:	nopl   0x0(%rax)
    4288:	mov    %r13,%rdi
    428b:	callq  2dd0 <crc32_combine64+0x1d0>
    4290:	mov    0xa4(%r13),%esi
    4297:	cmp    $0x2,%esi
    429a:	jbe    431c <deflateSetDictionary+0x11c>
    42a0:	mov    0x9c(%r13),%edx
    42a7:	mov    0x70(%r13),%eax
    42ab:	mov    0x80(%r13),%ecx
    42b2:	mov    0x50(%r13),%r15
    42b6:	mov    0x7c(%r13),%r14d
    42ba:	mov    0x60(%r13),%r11
    42be:	mov    0x4c(%r13),%r10d
    42c2:	mov    0x68(%r13),%r9
    42c6:	lea    -0x2(%rdx,%rsi,1),%r8d
    42cb:	mov    %rbx,(%rsp)
    42cf:	nop
    42d0:	lea    0x2(%rdx),%esi
    42d3:	shl    %cl,%eax
    42d5:	mov    %edx,%edi
    42d7:	and    %r10d,%edi
    42da:	movzbl (%r15,%rsi,1),%esi
    42df:	xor    %esi,%eax
    42e1:	and    %r14d,%eax
    42e4:	mov    %eax,%esi
    42e6:	mov    %eax,0x70(%r13)
    42ea:	lea    (%r9,%rsi,2),%rsi
    42ee:	movzwl (%rsi),%ebx
    42f1:	mov    %bx,(%r11,%rdi,2)
    42f6:	mov    %dx,(%rsi)
    42f9:	add    $0x1,%edx
    42fc:	cmp    %r8d,%edx
    42ff:	jne    42d0 <deflateSetDictionary+0xd0>
    4301:	mov    (%rsp),%rbx
    4305:	mov    %edx,0x9c(%r13)
    430c:	movl   $0x2,0xa4(%r13)
    4317:	jmpq   4288 <deflateSetDictionary+0x88>
    431c:	mov    %esi,%eax
    431e:	add    0x9c(%r13),%eax
    4325:	mov    %esi,0x171c(%r13)
    432c:	movl   $0x0,0xa4(%r13)
    4337:	movl   $0x2,0xa8(%r13)
    4342:	movl   $0x2,0x90(%r13)
    434d:	movl   $0x0,0x98(%r13)
    4358:	mov    %eax,0x9c(%r13)
    435f:	mov    %rax,0x88(%r13)
    4366:	mov    0xc(%rsp),%eax
    436a:	mov    %r12,(%rbx)
    436d:	mov    %eax,0x8(%rbx)
    4370:	mov    %ebp,0x2c(%r13)
    4374:	xor    %eax,%eax
    4376:	add    $0x18,%rsp
    437a:	pop    %rbx
    437b:	pop    %rbp
    437c:	pop    %r12
    437e:	pop    %r13
    4380:	pop    %r14
    4382:	pop    %r15
    4384:	retq   
    4385:	test   %ebp,%ebp
    4387:	je     43d7 <deflateSetDictionary+0x1d7>
    4389:	sub    %eax,%r14d
    438c:	add    %r14,%r15
    438f:	mov    %eax,%r14d
    4392:	jmpq   4270 <deflateSetDictionary+0x70>
    4397:	cmpl   $0x2a,0x8(%r13)
    439c:	mov    $0xfffffffe,%eax
    43a1:	jne    4376 <deflateSetDictionary+0x176>
    43a3:	mov    0xa4(%r13),%edx
    43aa:	test   %edx,%edx
    43ac:	jne    4376 <deflateSetDictionary+0x176>
    43ae:	mov    0x60(%rbx),%rdi
    43b2:	mov    %r14d,%edx
    43b5:	mov    %r15,%rsi
    43b8:	callq  1ef0 <adler32>
    43bd:	mov    %rax,0x60(%rbx)
    43c1:	mov    0x44(%r13),%eax
    43c5:	movl   $0x0,0x2c(%r13)
    43cd:	cmp    %eax,%r14d
    43d0:	jae    4389 <deflateSetDictionary+0x189>
    43d2:	jmpq   4270 <deflateSetDictionary+0x70>
    43d7:	mov    0x74(%r13),%eax
    43db:	mov    0x68(%r13),%rdi
    43df:	xor    %ecx,%ecx
    43e1:	xor    %esi,%esi
    43e3:	sub    $0x1,%eax
    43e6:	lea    (%rax,%rax,1),%rdx
    43ea:	mov    %cx,(%rdi,%rax,2)
    43ee:	callq  1d30 <memset@plt>
    43f3:	movl   $0x0,0x9c(%r13)
    43fe:	movq   $0x0,0x88(%r13)
    4409:	movl   $0x0,0x171c(%r13)
    4414:	mov    0x44(%r13),%eax
    4418:	jmpq   4389 <deflateSetDictionary+0x189>
    441d:	mov    $0xfffffffe,%eax
    4422:	jmpq   4376 <deflateSetDictionary+0x176>
    4427:	nopw   0x0(%rax,%rax,1)
