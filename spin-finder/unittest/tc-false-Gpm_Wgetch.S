// TC_OUT
0000000000003f50 <Gpm_Wgetch>:
    3f50:	push   %r15
    3f52:	push   %r14
    3f54:	push   %r13
    3f56:	push   %r12
    3f58:	push   %rbp
    3f59:	push   %rbx
    3f5a:	sub    $0xa8,%rsp
    3f61:	mov    %fs:0x28,%rax
    3f6a:	mov    %rax,0x98(%rsp)
    3f72:	xor    %eax,%eax
    3f74:	mov    0x20204d(%rip),%rax        # 205fc8 <_fini+0x201ba0>
    3f7b:	mov    %rdi,(%rsp)
    3f7f:	mov    (%rax),%r8d
    3f82:	test   %r8d,%r8d
    3f85:	je     40b8 <Gpm_Wgetch+0x168>
    3f8b:	mov    0x201f8e(%rip),%r13        # 205f20 <_fini+0x201af8>
    3f92:	mov    0x0(%r13),%r14d
    3f96:	cmp    $0xffffffff,%r14d
    3f9a:	je     40b8 <Gpm_Wgetch+0x168>
    3fa0:	mov    0x201fb1(%rip),%rax        # 205f58 <_fini+0x201b30>
    3fa7:	mov    (%rax),%edi
    3fa9:	test   %edi,%edi
    3fab:	jne    419b <Gpm_Wgetch+0x24b>
    3fb1:	mov    0x201f90(%rip),%rax        # 205f48 <_fini+0x201b20>
    3fb8:	test   %r14d,%r14d
    3fbb:	movl   $0x0,(%rax)
    3fc1:	js     416b <Gpm_Wgetch+0x21b>
    3fc7:	mov    0x201f72(%rip),%r15        # 205f40 <_fini+0x201b18>
    3fce:	mov    0x201fa3(%rip),%rbp        # 205f78 <_fini+0x201b50>
    3fd5:	lea    0x10(%rsp),%rbx
    3fda:	add    $0x1,%r14d
    3fde:	xor    %r12d,%r12d
    3fe1:	nopl   0x0(%rax)
    3fe8:	mov    (%r15),%esi
    3feb:	test   %esi,%esi
    3fed:	jne    40f8 <Gpm_Wgetch+0x1a8>
    3ff3:	nopl   0x0(%rax,%rax,1)
    3ff8:	mov    $0x10,%ecx
    3ffd:	mov    %rbx,%rdi
    4000:	mov    %r12d,%eax
    4003:	cld    
    4004:	rep stos %rax,%es:(%rdi)
    4007:	movslq 0x0(%r13),%rdi
    400b:	orq    $0x1,0x10(%rsp)
    4011:	test   %edi,%edi
    4013:	js     403a <Gpm_Wgetch+0xea>
    4015:	callq  1c50 <__fdelt_chk@plt>
    401a:	mov    0x0(%r13),%ecx
    401e:	mov    %ecx,%edx
    4020:	sar    $0x1f,%edx
    4023:	shr    $0x1a,%edx
    4026:	add    %edx,%ecx
    4028:	and    $0x3f,%ecx
    402b:	sub    %edx,%ecx
    402d:	mov    $0x1,%edx
    4032:	shl    %cl,%rdx
    4035:	or     %rdx,0x10(%rsp,%rax,8)
    403a:	xor    %ecx,%ecx
    403c:	xor    %edx,%edx
    403e:	mov    %rbp,%r8
    4041:	mov    %rbx,%rsi
    4044:	mov    %r14d,%edi
    4047:	movq   $0x2,0x0(%rbp)
    404f:	callq  1d70 <select@plt>
    4054:	test   %eax,%eax
    4056:	je     3ff8 <Gpm_Wgetch+0xa8>
    4058:	testb  $0x1,0x10(%rsp)
    405d:	jne    40b8 <Gpm_Wgetch+0x168>
    405f:	cmp    $0xffffffff,%eax
    4062:	je     3fe8 <Gpm_Wgetch+0x98>
    4064:	lea    0x2025d5(%rip),%rdi        # 206640 <gpm_roi+0x110>
    406b:	callq  1e40 <Gpm_GetEvent@plt>
    4070:	test   %eax,%eax
    4072:	je     3fe8 <Gpm_Wgetch+0x98>
    4078:	mov    0x201ee9(%rip),%rax        # 205f68 <_fini+0x201b40>
    407f:	mov    (%rax),%rax
    4082:	test   %rax,%rax
    4085:	je     3fe8 <Gpm_Wgetch+0x98>
    408b:	mov    0x201f0e(%rip),%rdx        # 205fa0 <_fini+0x201b78>
    4092:	lea    0x2025a7(%rip),%rdi        # 206640 <gpm_roi+0x110>
    4099:	mov    (%rdx),%rsi
    409c:	callq  *%rax
    409e:	test   %eax,%eax
    40a0:	je     3fe8 <Gpm_Wgetch+0x98>
    40a6:	mov    0x201e9b(%rip),%rsi        # 205f48 <_fini+0x201b20>
    40ad:	movl   $0x1,(%rsi)
    40b3:	jmp    40ca <Gpm_Wgetch+0x17a>
    40b5:	nopl   (%rax)
    40b8:	mov    (%rsp),%rdi
    40bc:	test   %rdi,%rdi
    40bf:	je     415c <Gpm_Wgetch+0x20c>
    40c5:	callq  1e30 <wgetch@plt>
    40ca:	mov    0x98(%rsp),%rsi
    40d2:	xor    %fs:0x28,%rsi
    40db:	jne    4421 <Gpm_Wgetch+0x4d1>
    40e1:	add    $0xa8,%rsp
    40e8:	pop    %rbx
    40e9:	pop    %rbp
    40ea:	pop    %r12
    40ec:	pop    %r13
    40ee:	pop    %r14
    40f0:	pop    %r15
    40f2:	retq   
    40f3:	nopl   0x0(%rax,%rax,1)
    40f8:	mov    0x201eb9(%rip),%rcx        # 205fb8 <_fini+0x201b90>
    40ff:	mov    0x201e82(%rip),%rax        # 205f88 <_fini+0x201b60>
    4106:	mov    0x201e73(%rip),%rdx        # 205f80 <_fini+0x201b58>
    410d:	mov    (%rcx),%ecx
    410f:	mov    (%rax),%rax
    4112:	movb   $0x2,0x1(%rdx)
    4116:	add    $0x1,%rdx
    411a:	mov    %ecx,%esi
    411c:	add    0x202525(%rip),%si        # 206648 <gpm_roi+0x118>
    4123:	mov    %si,(%rax)
    4126:	mov    %si,0x4(%rax)
    412a:	mov    $0x541c,%esi
    412f:	add    0x202514(%rip),%cx        # 20664a <gpm_roi+0x11a>
    4136:	mov    %cx,0x2(%rax)
    413a:	mov    %cx,0x6(%rax)
    413e:	mov    $0x3,%ecx
    4143:	mov    %cx,0x8(%rax)
    4147:	mov    0x201e5a(%rip),%rax        # 205fa8 <_fini+0x201b80>
    414e:	mov    (%rax),%edi
    4150:	xor    %eax,%eax
    4152:	callq  1c80 <ioctl@plt>
    4157:	jmpq   3ff8 <Gpm_Wgetch+0xa8>
    415c:	mov    0x201e2d(%rip),%rax        # 205f90 <_fini+0x201b68>
    4163:	mov    (%rax),%rdi
    4166:	jmpq   40c5 <Gpm_Wgetch+0x175>
    416b:	xor    %eax,%eax
    416d:	cmp    $0xfffffffe,%r14d
    4171:	jne    40ca <Gpm_Wgetch+0x17a>
    4177:	mov    0x2024b3(%rip),%eax        # 206630 <gpm_roi+0x100>
    417d:	test   %eax,%eax
    417f:	je     41ba <Gpm_Wgetch+0x26a>
    4181:	sub    $0x1,%eax
    4184:	lea    0x202495(%rip),%rdx        # 206620 <gpm_roi+0xf0>
    418b:	mov    %eax,0x20249f(%rip)        # 206630 <gpm_roi+0x100>
    4191:	cltq   
    4193:	mov    (%rdx,%rax,4),%eax
    4196:	jmpq   40ca <Gpm_Wgetch+0x17a>
    419b:	mov    0x201dfe(%rip),%rax        # 205fa0 <_fini+0x201b78>
    41a2:	lea    0x202497(%rip),%rdi        # 206640 <gpm_roi+0x110>
    41a9:	mov    (%rax),%rsi
    41ac:	mov    0x201db5(%rip),%rax        # 205f68 <_fini+0x201b40>
    41b3:	callq  *(%rax)
    41b5:	jmpq   40ca <Gpm_Wgetch+0x17a>
    41ba:	lea    0x90(%rsp),%rax
    41c2:	mov    0x201daf(%rip),%rbp        # 205f78 <_fini+0x201b50>
    41c9:	lea    0x2023d0(%rip),%r13        # 2065a0 <gpm_roi+0x70>
    41d0:	lea    0x93(%rsp),%r14
    41d8:	xor    %r12d,%r12d
    41db:	mov    $0x10,%ebx
    41e0:	mov    %rax,0x8(%rsp)
    41e5:	nopl   (%rax)
    41e8:	mov    %rbx,%rcx
    41eb:	mov    %r13,%rdi
    41ee:	mov    %r12d,%eax
    41f1:	cld    
    41f2:	rep stos %rax,%es:(%rdi)
    41f5:	lea    0x2023a4(%rip),%rsi        # 2065a0 <gpm_roi+0x70>
    41fc:	xor    %ecx,%ecx
    41fe:	xor    %edx,%edx
    4200:	mov    %rbp,%r8
    4203:	mov    $0x1,%edi
    4208:	orq    $0x1,0x202390(%rip)        # 2065a0 <gpm_roi+0x70>
    4210:	movq   $0x2,0x0(%rbp)
    4218:	callq  1d70 <select@plt>
    421d:	test   %eax,%eax
    421f:	je     41e8 <Gpm_Wgetch+0x298>
    4221:	mov    (%rsp),%rdi
    4225:	test   %rdi,%rdi
    4228:	je     438a <Gpm_Wgetch+0x43a>
    422e:	callq  1e30 <wgetch@plt>
    4233:	cmp    $0x1b,%eax
    4236:	jne    40ca <Gpm_Wgetch+0x17a>
    423c:	mov    %rbx,%rcx
    423f:	mov    %r13,%rdi
    4242:	mov    %r12d,%eax
    4245:	cld    
    4246:	rep stos %rax,%es:(%rdi)
    4249:	lea    0x201ff0(%rip),%r8        # 206240 <_gpm_arg+0x8>
    4250:	lea    0x202349(%rip),%rsi        # 2065a0 <gpm_roi+0x70>
    4257:	xor    %ecx,%ecx
    4259:	xor    %edx,%edx
    425b:	mov    $0x1,%edi
    4260:	orq    $0x1,0x202338(%rip)        # 2065a0 <gpm_roi+0x70>
    4268:	movq   $0x186a0,0x201fd5(%rip)        # 206248 <_gpm_arg+0x10>
    4273:	callq  1d70 <select@plt>
    4278:	test   %eax,%eax
    427a:	je     4417 <Gpm_Wgetch+0x4c7>
    4280:	mov    (%rsp),%rdi
    4284:	test   %rdi,%rdi
    4287:	je     437b <Gpm_Wgetch+0x42b>
    428d:	callq  1e30 <wgetch@plt>
    4292:	cmp    $0x5b,%eax
    4295:	jne    43c1 <Gpm_Wgetch+0x471>
    429b:	mov    %rbx,%rcx
    429e:	mov    %r13,%rdi
    42a1:	mov    %r12d,%eax
    42a4:	cld    
    42a5:	rep stos %rax,%es:(%rdi)
    42a8:	lea    0x201f91(%rip),%r8        # 206240 <_gpm_arg+0x8>
    42af:	lea    0x2022ea(%rip),%rsi        # 2065a0 <gpm_roi+0x70>
    42b6:	xor    %ecx,%ecx
    42b8:	xor    %edx,%edx
    42ba:	mov    $0x1,%edi
    42bf:	orq    $0x1,0x2022d9(%rip)        # 2065a0 <gpm_roi+0x70>
    42c7:	movq   $0x186a0,0x201f76(%rip)        # 206248 <_gpm_arg+0x10>
    42d2:	callq  1d70 <select@plt>
    42d7:	test   %eax,%eax
    42d9:	je     4399 <Gpm_Wgetch+0x449>
    42df:	mov    (%rsp),%rdi
    42e3:	test   %rdi,%rdi
    42e6:	je     436c <Gpm_Wgetch+0x41c>
    42ec:	callq  1e30 <wgetch@plt>
    42f1:	cmp    $0x4d,%eax
    42f4:	jne    43e5 <Gpm_Wgetch+0x495>
    42fa:	mov    0x8(%rsp),%r15
    42ff:	mov    (%rsp),%rdi
    4303:	test   %rdi,%rdi
    4306:	je     4360 <Gpm_Wgetch+0x410>
    4308:	callq  1e30 <wgetch@plt>
    430d:	add    $0x1,%r15
    4311:	mov    %al,-0x1(%r15)
    4315:	cmp    %r14,%r15
    4318:	jne    42ff <Gpm_Wgetch+0x3af>
    431a:	mov    0x8(%rsp),%rdi
    431f:	lea    0x20231a(%rip),%rsi        # 206640 <gpm_roi+0x110>
    4326:	callq  1f00 <gpm_convert_event@plt>
    432b:	mov    0x201c36(%rip),%rax        # 205f68 <_fini+0x201b40>
    4332:	mov    (%rax),%rax
    4335:	test   %rax,%rax
    4338:	je     41e8 <Gpm_Wgetch+0x298>
    433e:	mov    0x201c5b(%rip),%rdx        # 205fa0 <_fini+0x201b78>
    4345:	lea    0x2022f4(%rip),%rdi        # 206640 <gpm_roi+0x110>
    434c:	mov    (%rdx),%rsi
    434f:	callq  *%rax
    4351:	test   %eax,%eax
    4353:	je     41e8 <Gpm_Wgetch+0x298>
    4359:	jmpq   40a6 <Gpm_Wgetch+0x156>
    435e:	xchg   %ax,%ax
    4360:	mov    0x201c29(%rip),%rax        # 205f90 <_fini+0x201b68>
    4367:	mov    (%rax),%rdi
    436a:	jmp    4308 <Gpm_Wgetch+0x3b8>
    436c:	mov    0x201c1d(%rip),%rax        # 205f90 <_fini+0x201b68>
    4373:	mov    (%rax),%rdi
    4376:	jmpq   42ec <Gpm_Wgetch+0x39c>
    437b:	mov    0x201c0e(%rip),%rax        # 205f90 <_fini+0x201b68>
    4382:	mov    (%rax),%rdi
    4385:	jmpq   428d <Gpm_Wgetch+0x33d>
    438a:	mov    0x201bff(%rip),%rax        # 205f90 <_fini+0x201b68>
    4391:	mov    (%rax),%rdi
    4394:	jmpq   422e <Gpm_Wgetch+0x2de>
    4399:	movslq 0x202290(%rip),%rax        # 206630 <gpm_roi+0x100>
    43a0:	lea    0x1(%rax),%edx
    43a3:	mov    %edx,0x202287(%rip)        # 206630 <gpm_roi+0x100>
    43a9:	lea    0x202270(%rip),%rdx        # 206620 <gpm_roi+0xf0>
    43b0:	movl   $0x5b,(%rdx,%rax,4)
    43b7:	mov    $0x1b,%eax
    43bc:	jmpq   40ca <Gpm_Wgetch+0x17a>
    43c1:	movslq 0x202268(%rip),%rdx        # 206630 <gpm_roi+0x100>
    43c8:	lea    0x1(%rdx),%ecx
    43cb:	mov    %ecx,0x20225f(%rip)        # 206630 <gpm_roi+0x100>
    43d1:	lea    0x202248(%rip),%rcx        # 206620 <gpm_roi+0xf0>
    43d8:	mov    %eax,(%rcx,%rdx,4)
    43db:	mov    $0x1b,%eax
    43e0:	jmpq   40ca <Gpm_Wgetch+0x17a>
    43e5:	mov    0x202245(%rip),%edx        # 206630 <gpm_roi+0x100>
    43eb:	lea    0x20222e(%rip),%rcx        # 206620 <gpm_roi+0xf0>
    43f2:	movslq %edx,%rsi
    43f5:	mov    %eax,(%rcx,%rsi,4)
    43f8:	lea    0x2(%rdx),%eax
    43fb:	mov    %eax,0x20222f(%rip)        # 206630 <gpm_roi+0x100>
    4401:	lea    0x1(%rdx),%eax
    4404:	cltq   
    4406:	movl   $0x5b,(%rcx,%rax,4)
    440d:	mov    $0x1b,%eax
    4412:	jmpq   40ca <Gpm_Wgetch+0x17a>
    4417:	mov    $0x1b,%eax
    441c:	jmpq   40ca <Gpm_Wgetch+0x17a>
    4421:	callq  1c40 <__stack_chk_fail@plt>
    4426:	xchg   %ax,%ax
