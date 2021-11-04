
/home/woonhak/workspace/dark-insight-apps/splash-2x/parsec-3.0/ext/splash2x/apps/volrend/inst/amd64-linux.gcc/bin/volrend:     file format elf64-x86-64


Disassembly of section .init:

0000000000401088 <_init>:
  401088:	sub    $0x8,%rsp
  40108c:	mov    0x21df65(%rip),%rax        # 61eff8 <__gmon_start__>
  401093:	test   %rax,%rax
  401096:	je     40109a <_init+0x12>
  401098:	callq  *%rax
  40109a:	add    $0x8,%rsp
  40109e:	retq   

Disassembly of section .plt:

00000000004010a0 <.plt>:
  4010a0:	pushq  0x21df62(%rip)        # 61f008 <_GLOBAL_OFFSET_TABLE_+0x8>
  4010a6:	jmpq   *0x21df64(%rip)        # 61f010 <_GLOBAL_OFFSET_TABLE_+0x10>
  4010ac:	nopl   0x0(%rax)

00000000004010b0 <free@plt>:
  4010b0:	jmpq   *0x21df62(%rip)        # 61f018 <free@GLIBC_2.2.5>
  4010b6:	pushq  $0x0
  4010bb:	jmpq   4010a0 <.plt>

00000000004010c0 <putchar@plt>:
  4010c0:	jmpq   *0x21df5a(%rip)        # 61f020 <putchar@GLIBC_2.2.5>
  4010c6:	pushq  $0x1
  4010cb:	jmpq   4010a0 <.plt>

00000000004010d0 <pthread_create@plt>:
  4010d0:	jmpq   *0x21df52(%rip)        # 61f028 <pthread_create@GLIBC_2.2.5>
  4010d6:	pushq  $0x2
  4010db:	jmpq   4010a0 <.plt>

00000000004010e0 <strncmp@plt>:
  4010e0:	jmpq   *0x21df4a(%rip)        # 61f030 <strncmp@GLIBC_2.2.5>
  4010e6:	pushq  $0x3
  4010eb:	jmpq   4010a0 <.plt>

00000000004010f0 <strcpy@plt>:
  4010f0:	jmpq   *0x21df42(%rip)        # 61f038 <strcpy@GLIBC_2.2.5>
  4010f6:	pushq  $0x4
  4010fb:	jmpq   4010a0 <.plt>

0000000000401100 <pthread_cond_broadcast@plt>:
  401100:	jmpq   *0x21df3a(%rip)        # 61f040 <pthread_cond_broadcast@GLIBC_2.3.2>
  401106:	pushq  $0x5
  40110b:	jmpq   4010a0 <.plt>

0000000000401110 <puts@plt>:
  401110:	jmpq   *0x21df32(%rip)        # 61f048 <puts@GLIBC_2.2.5>
  401116:	pushq  $0x6
  40111b:	jmpq   4010a0 <.plt>

0000000000401120 <write@plt>:
  401120:	jmpq   *0x21df2a(%rip)        # 61f050 <write@GLIBC_2.2.5>
  401126:	pushq  $0x7
  40112b:	jmpq   4010a0 <.plt>

0000000000401130 <pthread_cond_wait@plt>:
  401130:	jmpq   *0x21df22(%rip)        # 61f058 <pthread_cond_wait@GLIBC_2.3.2>
  401136:	pushq  $0x8
  40113b:	jmpq   4010a0 <.plt>

0000000000401140 <stpcpy@plt>:
  401140:	jmpq   *0x21df1a(%rip)        # 61f060 <stpcpy@GLIBC_2.2.5>
  401146:	pushq  $0x9
  40114b:	jmpq   4010a0 <.plt>

0000000000401150 <mmap@plt>:
  401150:	jmpq   *0x21df12(%rip)        # 61f068 <mmap@GLIBC_2.2.5>
  401156:	pushq  $0xa
  40115b:	jmpq   4010a0 <.plt>

0000000000401160 <pthread_setcancelstate@plt>:
  401160:	jmpq   *0x21df0a(%rip)        # 61f070 <pthread_setcancelstate@GLIBC_2.2.5>
  401166:	pushq  $0xb
  40116b:	jmpq   4010a0 <.plt>

0000000000401170 <printf@plt>:
  401170:	jmpq   *0x21df02(%rip)        # 61f078 <printf@GLIBC_2.2.5>
  401176:	pushq  $0xc
  40117b:	jmpq   4010a0 <.plt>

0000000000401180 <pthread_mutex_destroy@plt>:
  401180:	jmpq   *0x21defa(%rip)        # 61f080 <pthread_mutex_destroy@GLIBC_2.2.5>
  401186:	pushq  $0xd
  40118b:	jmpq   4010a0 <.plt>

0000000000401190 <lseek@plt>:
  401190:	jmpq   *0x21def2(%rip)        # 61f088 <lseek@GLIBC_2.2.5>
  401196:	pushq  $0xe
  40119b:	jmpq   4010a0 <.plt>

00000000004011a0 <gettimeofday@plt>:
  4011a0:	jmpq   *0x21deea(%rip)        # 61f090 <gettimeofday@GLIBC_2.2.5>
  4011a6:	pushq  $0xf
  4011ab:	jmpq   4010a0 <.plt>

00000000004011b0 <__assert_fail@plt>:
  4011b0:	jmpq   *0x21dee2(%rip)        # 61f098 <__assert_fail@GLIBC_2.2.5>
  4011b6:	pushq  $0x10
  4011bb:	jmpq   4010a0 <.plt>

00000000004011c0 <memset@plt>:
  4011c0:	jmpq   *0x21deda(%rip)        # 61f0a0 <memset@GLIBC_2.2.5>
  4011c6:	pushq  $0x11
  4011cb:	jmpq   4010a0 <.plt>

00000000004011d0 <pow@plt>:
  4011d0:	jmpq   *0x21ded2(%rip)        # 61f0a8 <pow@GLIBC_2.2.5>
  4011d6:	pushq  $0x12
  4011db:	jmpq   4010a0 <.plt>

00000000004011e0 <sincos@plt>:
  4011e0:	jmpq   *0x21deca(%rip)        # 61f0b0 <sincos@GLIBC_2.2.5>
  4011e6:	pushq  $0x13
  4011eb:	jmpq   4010a0 <.plt>

00000000004011f0 <close@plt>:
  4011f0:	jmpq   *0x21dec2(%rip)        # 61f0b8 <close@GLIBC_2.2.5>
  4011f6:	pushq  $0x14
  4011fb:	jmpq   4010a0 <.plt>

0000000000401200 <read@plt>:
  401200:	jmpq   *0x21deba(%rip)        # 61f0c0 <read@GLIBC_2.2.5>
  401206:	pushq  $0x15
  40120b:	jmpq   4010a0 <.plt>

0000000000401210 <calloc@plt>:
  401210:	jmpq   *0x21deb2(%rip)        # 61f0c8 <calloc@GLIBC_2.2.5>
  401216:	pushq  $0x16
  40121b:	jmpq   4010a0 <.plt>

0000000000401220 <fprintf@plt>:
  401220:	jmpq   *0x21deaa(%rip)        # 61f0d0 <fprintf@GLIBC_2.2.5>
  401226:	pushq  $0x17
  40122b:	jmpq   4010a0 <.plt>

0000000000401230 <strtol@plt>:
  401230:	jmpq   *0x21dea2(%rip)        # 61f0d8 <strtol@GLIBC_2.2.5>
  401236:	pushq  $0x18
  40123b:	jmpq   4010a0 <.plt>

0000000000401240 <sqrtf@plt>:
  401240:	jmpq   *0x21de9a(%rip)        # 61f0e0 <sqrtf@GLIBC_2.2.5>
  401246:	pushq  $0x19
  40124b:	jmpq   4010a0 <.plt>

0000000000401250 <pthread_cond_init@plt>:
  401250:	jmpq   *0x21de92(%rip)        # 61f0e8 <pthread_cond_init@GLIBC_2.3.2>
  401256:	pushq  $0x1a
  40125b:	jmpq   4010a0 <.plt>

0000000000401260 <pthread_mutex_unlock@plt>:
  401260:	jmpq   *0x21de8a(%rip)        # 61f0f0 <pthread_mutex_unlock@GLIBC_2.2.5>
  401266:	pushq  $0x1b
  40126b:	jmpq   4010a0 <.plt>

0000000000401270 <malloc@plt>:
  401270:	jmpq   *0x21de82(%rip)        # 61f0f8 <malloc@GLIBC_2.2.5>
  401276:	pushq  $0x1c
  40127b:	jmpq   4010a0 <.plt>

0000000000401280 <fflush@plt>:
  401280:	jmpq   *0x21de7a(%rip)        # 61f100 <fflush@GLIBC_2.2.5>
  401286:	pushq  $0x1d
  40128b:	jmpq   4010a0 <.plt>

0000000000401290 <__fxstat@plt>:
  401290:	jmpq   *0x21de72(%rip)        # 61f108 <__fxstat@GLIBC_2.2.5>
  401296:	pushq  $0x1e
  40129b:	jmpq   4010a0 <.plt>

00000000004012a0 <bcmp@plt>:
  4012a0:	jmpq   *0x21de6a(%rip)        # 61f110 <bcmp@GLIBC_2.2.5>
  4012a6:	pushq  $0x1f
  4012ab:	jmpq   4010a0 <.plt>

00000000004012b0 <realloc@plt>:
  4012b0:	jmpq   *0x21de62(%rip)        # 61f118 <realloc@GLIBC_2.2.5>
  4012b6:	pushq  $0x20
  4012bb:	jmpq   4010a0 <.plt>

00000000004012c0 <munmap@plt>:
  4012c0:	jmpq   *0x21de5a(%rip)        # 61f120 <munmap@GLIBC_2.2.5>
  4012c6:	pushq  $0x21
  4012cb:	jmpq   4010a0 <.plt>

00000000004012d0 <bcopy@plt>:
  4012d0:	jmpq   *0x21de52(%rip)        # 61f128 <bcopy@GLIBC_2.2.5>
  4012d6:	pushq  $0x22
  4012db:	jmpq   4010a0 <.plt>

00000000004012e0 <open@plt>:
  4012e0:	jmpq   *0x21de4a(%rip)        # 61f130 <open@GLIBC_2.2.5>
  4012e6:	pushq  $0x23
  4012eb:	jmpq   4010a0 <.plt>

00000000004012f0 <bzero@plt>:
  4012f0:	jmpq   *0x21de42(%rip)        # 61f138 <bzero@GLIBC_2.2.5>
  4012f6:	pushq  $0x24
  4012fb:	jmpq   4010a0 <.plt>

0000000000401300 <pthread_join@plt>:
  401300:	jmpq   *0x21de3a(%rip)        # 61f140 <pthread_join@GLIBC_2.2.5>
  401306:	pushq  $0x25
  40130b:	jmpq   4010a0 <.plt>

0000000000401310 <vfprintf@plt>:
  401310:	jmpq   *0x21de32(%rip)        # 61f148 <vfprintf@GLIBC_2.2.5>
  401316:	pushq  $0x26
  40131b:	jmpq   4010a0 <.plt>

0000000000401320 <creat@plt>:
  401320:	jmpq   *0x21de2a(%rip)        # 61f150 <creat@GLIBC_2.2.5>
  401326:	pushq  $0x27
  40132b:	jmpq   4010a0 <.plt>

0000000000401330 <sprintf@plt>:
  401330:	jmpq   *0x21de22(%rip)        # 61f158 <sprintf@GLIBC_2.2.5>
  401336:	pushq  $0x28
  40133b:	jmpq   4010a0 <.plt>

0000000000401340 <exit@plt>:
  401340:	jmpq   *0x21de1a(%rip)        # 61f160 <exit@GLIBC_2.2.5>
  401346:	pushq  $0x29
  40134b:	jmpq   4010a0 <.plt>

0000000000401350 <fwrite@plt>:
  401350:	jmpq   *0x21de12(%rip)        # 61f168 <fwrite@GLIBC_2.2.5>
  401356:	pushq  $0x2a
  40135b:	jmpq   4010a0 <.plt>

0000000000401360 <sqrt@plt>:
  401360:	jmpq   *0x21de0a(%rip)        # 61f170 <sqrt@GLIBC_2.2.5>
  401366:	pushq  $0x2b
  40136b:	jmpq   4010a0 <.plt>

0000000000401370 <pthread_mutex_init@plt>:
  401370:	jmpq   *0x21de02(%rip)        # 61f178 <pthread_mutex_init@GLIBC_2.2.5>
  401376:	pushq  $0x2c
  40137b:	jmpq   4010a0 <.plt>

0000000000401380 <pthread_mutex_lock@plt>:
  401380:	jmpq   *0x21ddfa(%rip)        # 61f180 <pthread_mutex_lock@GLIBC_2.2.5>
  401386:	pushq  $0x2d
  40138b:	jmpq   4010a0 <.plt>

Disassembly of section .text:

0000000000401390 <main>:
  401390:	push   %rbp
  401391:	push   %rbx
  401392:	sub    $0x8,%rsp
  401396:	cmp    $0x3,%edi
  401399:	jle    4013b5 <main+0x25>
  40139b:	mov    0x8(%rsi),%rax
  40139f:	mov    %edi,%ebp
  4013a1:	mov    %rsi,%rbx
  4013a4:	mov    $0x419194,%edi
  4013a9:	mov    $0x2,%ecx
  4013ae:	mov    %rax,%rsi
  4013b1:	repz cmpsb %es:(%rdi),%ds:(%rsi)
  4013b3:	jne    4013c9 <main+0x39>
  4013b5:	mov    $0x4190e8,%edi
  4013ba:	callq  401110 <puts@plt>
  4013bf:	mov    $0xffffffff,%edi
  4013c4:	callq  401340 <exit@plt>
  4013c9:	xor    %esi,%esi
  4013cb:	mov    $0xa,%edx
  4013d0:	mov    %rax,%rdi
  4013d3:	callq  401230 <strtol@plt>
  4013d8:	mov    0x18(%rbx),%rdi
  4013dc:	xor    %esi,%esi
  4013de:	mov    $0xa,%edx
  4013e3:	mov    %rax,0x243066(%rip)        # 644450 <num_nodes>
  4013ea:	callq  401230 <strtol@plt>
  4013ef:	mov    0x10(%rbx),%rsi
  4013f3:	mov    $0x644340,%edi
  4013f8:	mov    %eax,0x21dda6(%rip)        # 61f1a4 <ROTATE_STEPS>
  4013fe:	callq  4010f0 <strcpy@plt>
  401403:	cmp    $0x5,%ebp
  401406:	jne    401428 <main+0x98>
  401408:	mov    0x20(%rbx),%rdi
  40140c:	mov    $0x2,%edx
  401411:	mov    $0x419197,%esi
  401416:	callq  4010e0 <strncmp@plt>
  40141b:	test   %eax,%eax
  40141d:	jne    401480 <main+0xf0>
  40141f:	movw   $0x1,0x243d94(%rip)        # 6451bc <adaptive>
  401428:	callq  405650 <Frame>
  40142d:	cmpq   $0x1,0x24301b(%rip)        # 644450 <num_nodes>
  401435:	jle    401479 <main+0xe9>
  401437:	xor    %ebp,%ebp
  401439:	jmp    401454 <main+0xc4>
  40143b:	nopl   0x0(%rax,%rax,1)
  401440:	mov    0x243009(%rip),%rdx        # 644450 <num_nodes>
  401447:	add    $0x1,%rbp
  40144b:	sub    $0x1,%rdx
  40144f:	cmp    %rbp,%rdx
  401452:	jbe    401479 <main+0xe9>
  401454:	mov    0x642320(,%rbp,8),%rdi
  40145c:	xor    %esi,%esi
  40145e:	callq  401300 <pthread_join@plt>
  401463:	test   %eax,%eax
  401465:	je     401440 <main+0xb0>
  401467:	mov    $0x41919a,%edi
  40146c:	callq  401110 <puts@plt>
  401471:	or     $0xffffffff,%edi
  401474:	callq  401340 <exit@plt>
  401479:	xor    %edi,%edi
  40147b:	callq  401340 <exit@plt>
  401480:	mov    $0x419120,%edi
  401485:	callq  401110 <puts@plt>
  40148a:	or     $0xffffffff,%edi
  40148d:	callq  401340 <exit@plt>
  401492:	nopw   %cs:0x0(%rax,%rax,1)
  40149c:	nopl   0x0(%rax)

00000000004014a0 <_start>:
  4014a0:	xor    %ebp,%ebp
  4014a2:	mov    %rdx,%r9
  4014a5:	pop    %rsi
  4014a6:	mov    %rsp,%rdx
  4014a9:	and    $0xfffffffffffffff0,%rsp
  4014ad:	push   %rax
  4014ae:	push   %rsp
  4014af:	mov    $0x418da0,%r8
  4014b6:	mov    $0x418d30,%rcx
  4014bd:	mov    $0x401390,%rdi
  4014c4:	callq  *0x21db26(%rip)        # 61eff0 <__libc_start_main@GLIBC_2.2.5>
  4014ca:	hlt    
  4014cb:	nopl   0x0(%rax,%rax,1)

00000000004014d0 <deregister_tm_clones>:
  4014d0:	push   %rbp
  4014d1:	mov    $0x642170,%eax
  4014d6:	cmp    $0x642170,%rax
  4014dc:	mov    %rsp,%rbp
  4014df:	je     4014f8 <deregister_tm_clones+0x28>
  4014e1:	mov    $0x0,%eax
  4014e6:	test   %rax,%rax
  4014e9:	je     4014f8 <deregister_tm_clones+0x28>
  4014eb:	pop    %rbp
  4014ec:	mov    $0x642170,%edi
  4014f1:	jmpq   *%rax
  4014f3:	nopl   0x0(%rax,%rax,1)
  4014f8:	pop    %rbp
  4014f9:	retq   
  4014fa:	nopw   0x0(%rax,%rax,1)

0000000000401500 <register_tm_clones>:
  401500:	mov    $0x642170,%esi
  401505:	push   %rbp
  401506:	sub    $0x642170,%rsi
  40150d:	mov    %rsp,%rbp
  401510:	sar    $0x3,%rsi
  401514:	mov    %rsi,%rax
  401517:	shr    $0x3f,%rax
  40151b:	add    %rax,%rsi
  40151e:	sar    %rsi
  401521:	je     401538 <register_tm_clones+0x38>
  401523:	mov    $0x0,%eax
  401528:	test   %rax,%rax
  40152b:	je     401538 <register_tm_clones+0x38>
  40152d:	pop    %rbp
  40152e:	mov    $0x642170,%edi
  401533:	jmpq   *%rax
  401535:	nopl   (%rax)
  401538:	pop    %rbp
  401539:	retq   
  40153a:	nopw   0x0(%rax,%rax,1)

0000000000401540 <__do_global_dtors_aux>:
  401540:	cmpb   $0x0,0x240c61(%rip)        # 6421a8 <completed.6991>
  401547:	jne    401560 <__do_global_dtors_aux+0x20>
  401549:	push   %rbp
  40154a:	mov    %rsp,%rbp
  40154d:	callq  4014d0 <deregister_tm_clones>
  401552:	movb   $0x1,0x240c4f(%rip)        # 6421a8 <completed.6991>
  401559:	pop    %rbp
  40155a:	retq   
  40155b:	nopl   0x0(%rax,%rax,1)
  401560:	repz retq 
  401562:	nopl   0x0(%rax)
  401566:	nopw   %cs:0x0(%rax,%rax,1)

0000000000401570 <frame_dummy>:
  401570:	push   %rbp
  401571:	mov    %rsp,%rbp
  401574:	pop    %rbp
  401575:	jmp    401500 <register_tm_clones>
  401577:	nopw   0x0(%rax,%rax,1)

0000000000401580 <Ray_Trace_Adaptive_Box>:
  401580:	push   %r15
  401582:	push   %r14
  401584:	push   %r13
  401586:	push   %r12
  401588:	push   %rbp
  401589:	push   %rbx
  40158a:	mov    %rdi,%rbp
  40158d:	mov    %rdx,%rbx
  401590:	sub    $0x28,%rsp
  401594:	test   %rdx,%rdx
  401597:	mov    %rsi,0x8(%rsp)
  40159c:	js     4017f5 <Ray_Trace_Adaptive_Box+0x275>
  4015a2:	mov    0x242e7f(%rip),%r14        # 644428 <image_len+0x8>
  4015a9:	mov    %rdx,%r12
  4015ac:	mov    %rsi,%r15
  4015af:	sub    %rdi,%r12
  4015b2:	cmp    %r14,%rsi
  4015b5:	jge    4017f5 <Ray_Trace_Adaptive_Box+0x275>
  4015bb:	mov    %r14,%rdx
  4015be:	mov    %r12,%r14
  4015c1:	mov    0x8(%rsp),%r12
  4015c6:	nopw   %cs:0x0(%rax,%rax,1)
  4015d0:	cmp    0x242e49(%rip),%rbp        # 644420 <image_len>
  4015d7:	mov    %rbp,%r13
  4015da:	jl     4015fd <Ray_Trace_Adaptive_Box+0x7d>
  4015dc:	jmpq   401677 <Ray_Trace_Adaptive_Box+0xf7>
  4015e1:	nopl   0x0(%rax)
  4015e8:	lea    (%r14,%r13,1),%r8
  4015ec:	cmp    %r8,%rbx
  4015ef:	jl     401670 <Ray_Trace_Adaptive_Box+0xf0>
  4015f1:	add    %rbx,%r13
  4015f4:	cmp    %r13,0x242e25(%rip)        # 644420 <image_len>
  4015fb:	jle    401670 <Ray_Trace_Adaptive_Box+0xf0>
  4015fd:	mov    0x240cec(%rip),%rcx        # 6422f0 <mask_image_len>
  401604:	imul   %r15,%rcx
  401608:	add    %r13,%rcx
  40160b:	add    0x240c8e(%rip),%rcx        # 6422a0 <mask_image_address>
  401612:	cmpb   $0x0,(%rcx)
  401615:	jne    4015e8 <Ray_Trace_Adaptive_Box+0x68>
  401617:	pxor   %xmm1,%xmm1
  40161b:	movb   $0x1,(%rcx)
  40161e:	mov    0x242dfb(%rip),%rdi        # 644420 <image_len>
  401625:	pxor   %xmm0,%xmm0
  401629:	cvtsi2ss %r15,%xmm1
  40162e:	imul   %r15,%rdi
  401632:	cvtsi2ss %r13,%xmm0
  401637:	add    %r13,%rdi
  40163a:	add    0x240c9f(%rip),%rdi        # 6422e0 <image_address>
  401641:	cvtss2sd %xmm1,%xmm1
  401645:	cvtss2sd %xmm0,%xmm0
  401649:	callq  4092f0 <Trace_Ray>
  40164e:	mov    0x240c9b(%rip),%rsi        # 6422f0 <mask_image_len>
  401655:	mov    0x240c44(%rip),%rdi        # 6422a0 <mask_image_address>
  40165c:	lea    (%r14,%r13,1),%r8
  401660:	imul   %r15,%rsi
  401664:	add    %r13,%rdi
  401667:	cmp    %r8,%rbx
  40166a:	movb   $0x80,(%rdi,%rsi,1)
  40166e:	jge    4015f1 <Ray_Trace_Adaptive_Box+0x71>
  401670:	mov    0x242db1(%rip),%rdx        # 644428 <image_len+0x8>
  401677:	mov    %rbx,%r9
  40167a:	sub    %r12,%r9
  40167d:	add    %r15,%r9
  401680:	cmp    %r9,%rbx
  401683:	jl     401691 <Ray_Trace_Adaptive_Box+0x111>
  401685:	add    %rbx,%r15
  401688:	cmp    %r15,%rdx
  40168b:	jg     4015d0 <Ray_Trace_Adaptive_Box+0x50>
  401691:	mov    0x8(%rsp),%r15
  401696:	mov    %rdx,%r14
  401699:	cmp    %rdx,%r15
  40169c:	jge    4017f5 <Ray_Trace_Adaptive_Box+0x275>
  4016a2:	mov    0x240c47(%rip),%rax        # 6422f0 <mask_image_len>
  4016a9:	mov    0x242d70(%rip),%r10        # 644420 <image_len>
  4016b0:	mov    %r15,%r9
  4016b3:	mov    %rbx,%r13
  4016b6:	xor    %esi,%esi
  4016b8:	mov    $0xff,%edi
  4016bd:	mov    %rax,%r12
  4016c0:	mov    %r10,%r11
  4016c3:	imul   %r15,%rax
  4016c7:	sub    %rbx,%r15
  4016ca:	imul   %r10,%r9
  4016ce:	imul   %rbx,%r11
  4016d2:	lea    (%rax,%rbp,1),%r8
  4016d6:	add    %rbp,%r9
  4016d9:	sub    %rbx,%r9
  4016dc:	sub    %rbx,%r8
  4016df:	add    0x240bfa(%rip),%r9        # 6422e0 <image_address>
  4016e6:	imul   %rbx,%r12
  4016ea:	add    0x240baf(%rip),%r8        # 6422a0 <mask_image_address>
  4016f1:	mov    %r11,(%rsp)
  4016f5:	mov    %rbp,%r11
  4016f8:	sub    %rbx,%r11
  4016fb:	nopl   0x0(%rax,%rax,1)
  401700:	cmp    %r10,%rbp
  401703:	mov    %rbx,%rcx
  401706:	jge    40174c <Ray_Trace_Adaptive_Box+0x1cc>
  401708:	nopl   0x0(%rax,%rax,1)
  401710:	movzbl (%r8,%rcx,1),%edx
  401715:	nopl   (%rax)
  401718:	mov    %rdx,0x18(%rsp)
  40171d:	mov    0x18(%rsp),%rax
  401722:	cmp    $0x1,%rax
  401726:	je     401718 <Ray_Trace_Adaptive_Box+0x198>
  401728:	movzbl (%r9,%rcx,1),%edx
  40172d:	cmp    %rdx,%rdi
  401730:	cmovg  %rdx,%rdi
  401734:	cmp    %rdx,%rsi
  401737:	cmovl  %rdx,%rsi
  40173b:	cmp    %rbx,%rcx
  40173e:	jg     40174c <Ray_Trace_Adaptive_Box+0x1cc>
  401740:	add    %rbx,%rcx
  401743:	lea    (%r11,%rcx,1),%rax
  401747:	cmp    %r10,%rax
  40174a:	jl     401710 <Ray_Trace_Adaptive_Box+0x190>
  40174c:	cmp    %r13,%rbx
  40174f:	jl     401764 <Ray_Trace_Adaptive_Box+0x1e4>
  401751:	add    %rbx,%r13
  401754:	add    (%rsp),%r9
  401758:	add    %r12,%r8
  40175b:	lea    (%r15,%r13,1),%rcx
  40175f:	cmp    %rcx,%r14
  401762:	jg     401700 <Ray_Trace_Adaptive_Box+0x180>
  401764:	cmp    %rbx,0x243a6d(%rip)        # 6451d8 <lowest_volume_boxlen>
  40176b:	jge    4017e6 <Ray_Trace_Adaptive_Box+0x266>
  40176d:	sub    %rdi,%rsi
  401770:	cmp    0x242ed1(%rip),%rsi        # 644648 <volume_color_difference>
  401777:	jl     4017e6 <Ray_Trace_Adaptive_Box+0x266>
  401779:	mov    %rbx,%r15
  40177c:	sar    %r15
  40177f:	test   %rbx,%rbx
  401782:	jle    4017e6 <Ray_Trace_Adaptive_Box+0x266>
  401784:	mov    %r15,%r12
  401787:	mov    0x8(%rsp),%r10
  40178c:	sub    %rbp,%r12
  40178f:	cmp    %r10,0x242c92(%rip)        # 644428 <image_len+0x8>
  401796:	mov    %r10,%r14
  401799:	jle    4017e6 <Ray_Trace_Adaptive_Box+0x266>
  40179b:	cmp    0x242c7e(%rip),%rbp        # 644420 <image_len>
  4017a2:	mov    %rbp,%r13
  4017a5:	jge    4017ca <Ray_Trace_Adaptive_Box+0x24a>
  4017a7:	mov    %r15,%rdx
  4017aa:	mov    %r14,%rsi
  4017ad:	mov    %r13,%rdi
  4017b0:	callq  401580 <Ray_Trace_Adaptive_Box>
  4017b5:	lea    (%r12,%r13,1),%r9
  4017b9:	cmp    %rbx,%r9
  4017bc:	jge    4017ca <Ray_Trace_Adaptive_Box+0x24a>
  4017be:	add    %r15,%r13
  4017c1:	cmp    %r13,0x242c58(%rip)        # 644420 <image_len>
  4017c8:	jg     4017a7 <Ray_Trace_Adaptive_Box+0x227>
  4017ca:	mov    %r15,%r8
  4017cd:	sub    0x8(%rsp),%r8
  4017d2:	add    %r14,%r8
  4017d5:	cmp    %r8,%rbx
  4017d8:	jle    4017e6 <Ray_Trace_Adaptive_Box+0x266>
  4017da:	add    %r15,%r14
  4017dd:	cmp    %r14,0x242c44(%rip)        # 644428 <image_len+0x8>
  4017e4:	jg     40179b <Ray_Trace_Adaptive_Box+0x21b>
  4017e6:	add    $0x28,%rsp
  4017ea:	pop    %rbx
  4017eb:	pop    %rbp
  4017ec:	pop    %r12
  4017ee:	pop    %r13
  4017f0:	pop    %r14
  4017f2:	pop    %r15
  4017f4:	retq   
  4017f5:	xor    %esi,%esi
  4017f7:	mov    $0xff,%edi
  4017fc:	jmpq   401764 <Ray_Trace_Adaptive_Box+0x1e4>
  401801:	nopl   0x0(%rax,%rax,1)
  401806:	nopw   %cs:0x0(%rax,%rax,1)

0000000000401810 <Ray_Trace_Adaptively>:
  401810:	push   %r15
  401812:	pxor   %xmm0,%xmm0
  401816:	push   %r14
  401818:	pxor   %xmm1,%xmm1
  40181c:	push   %r13
  40181e:	push   %r12
  401820:	push   %rbp
  401821:	push   %rbx
  401822:	pxor   %xmm3,%xmm3
  401826:	sub    $0x58,%rsp
  40182a:	movq   $0x0,0x240a23(%rip)        # 642258 <itest>
  401835:	cvtsi2ssq 0x242be2(%rip),%xmm0        # 644420 <image_len>
  40183e:	mov    %rdi,0x48(%rsp)
  401843:	cvtsi2ssq 0x242c14(%rip),%xmm1        # 644460 <image_section>
  40184c:	divss  %xmm1,%xmm0
  401850:	cvttss2si %xmm0,%rax
  401855:	cvtsi2ss %rax,%xmm3
  40185a:	mov    %rax,0x38(%rsp)
  40185f:	ucomiss %xmm3,%xmm0
  401862:	jp     401866 <Ray_Trace_Adaptively+0x56>
  401864:	je     401877 <Ray_Trace_Adaptively+0x67>
  401866:	addq   $0x1,0x38(%rsp)
  40186c:	pxor   %xmm3,%xmm3
  401870:	cvtsi2ssq 0x38(%rsp),%xmm3
  401877:	pxor   %xmm2,%xmm2
  40187b:	pxor   %xmm4,%xmm4
  40187f:	pxor   %xmm5,%xmm5
  401883:	cvtsi2ssq 0x242b9c(%rip),%xmm2        # 644428 <image_len+0x8>
  40188c:	cvtsi2ssq 0x242bd3(%rip),%xmm4        # 644468 <image_section+0x8>
  401895:	divss  %xmm4,%xmm2
  401899:	cvttss2si %xmm2,%rdx
  40189e:	cvtsi2ss %rdx,%xmm5
  4018a3:	mov    %rdx,0x40(%rsp)
  4018a8:	ucomiss %xmm5,%xmm2
  4018ab:	jp     4018af <Ray_Trace_Adaptively+0x9f>
  4018ad:	je     4018c0 <Ray_Trace_Adaptively+0xb0>
  4018af:	addq   $0x1,0x40(%rsp)
  4018b5:	pxor   %xmm5,%xmm5
  4018b9:	cvtsi2ssq 0x40(%rsp),%xmm5
  4018c0:	pxor   %xmm6,%xmm6
  4018c4:	pxor   %xmm7,%xmm7
  4018c8:	cvtsi2ssq 0x24390f(%rip),%xmm6        # 6451e0 <block_xlen>
  4018d1:	divss  %xmm6,%xmm3
  4018d5:	cvttss2si %xmm3,%rcx
  4018da:	cvtsi2ss %rcx,%xmm7
  4018df:	mov    %rcx,0x8(%rsp)
  4018e4:	ucomiss %xmm7,%xmm3
  4018e7:	jp     4018eb <Ray_Trace_Adaptively+0xdb>
  4018e9:	je     4018f1 <Ray_Trace_Adaptively+0xe1>
  4018eb:	addq   $0x1,0x8(%rsp)
  4018f1:	pxor   %xmm8,%xmm8
  4018f6:	pxor   %xmm9,%xmm9
  4018fb:	cvtsi2ssq 0x24389c(%rip),%xmm8        # 6451a0 <block_ylen>
  401904:	divss  %xmm8,%xmm5
  401909:	cvttss2si %xmm5,%rbx
  40190e:	cvtsi2ss %rbx,%xmm9
  401913:	ucomiss %xmm9,%xmm5
  401917:	jp     40191b <Ray_Trace_Adaptively+0x10b>
  401919:	je     40191f <Ray_Trace_Adaptively+0x10f>
  40191b:	add    $0x1,%rbx
  40191f:	imul   0x8(%rsp),%rbx
  401925:	mov    0x48(%rsp),%rdi
  40192a:	mov    0x2409a7(%rip),%rsi        # 6422d8 <Global>
  401931:	mov    0x242b18(%rip),%r11        # 644450 <num_nodes>
  401938:	mov    %rdi,%rbp
  40193b:	mov    %rdi,0x30(%rsp)
  401940:	shl    $0xb,%rbp
  401944:	add    %rsi,%rbp
  401947:	mov    %rbx,(%rsp)
  40194b:	movq   $0x0,0x10(%rbp)
  401953:	shl    $0xb,%r11
  401957:	lea    (%rsi,%r11,1),%r8
  40195b:	mov    0x10(%r8),%r9
  40195f:	test   %r9,%r9
  401962:	jle    401c69 <Ray_Trace_Adaptively+0x459>
  401968:	mov    0x30(%rsp),%rax
  40196d:	mov    0x2437fc(%rip),%r10        # 645170 <highest_sampling_boxlen>
  401974:	pxor   %xmm10,%xmm10
  401979:	pxor   %xmm11,%xmm11
  40197e:	cqto   
  401980:	pxor   %xmm12,%xmm12
  401985:	idivq  0x242ad4(%rip)        # 644460 <image_section>
  40198c:	cvtsi2ss %r10,%xmm10
  401991:	imul   0x38(%rsp),%rdx
  401997:	cvtsi2ss %rdx,%xmm11
  40199c:	divss  %xmm10,%xmm11
  4019a1:	cvttss2si %xmm11,%r11
  4019a6:	cvtsi2ss %r11,%xmm12
  4019ab:	ucomiss %xmm12,%xmm11
  4019af:	jp     4019b3 <Ray_Trace_Adaptively+0x1a3>
  4019b1:	je     4019b7 <Ray_Trace_Adaptively+0x1a7>
  4019b3:	add    $0x1,%r11
  4019b7:	imul   %r10,%r11
  4019bb:	mov    0x38(%rsp),%rbx
  4019c0:	pxor   %xmm13,%xmm13
  4019c5:	pxor   %xmm14,%xmm14
  4019ca:	add    %r11,%rbx
  4019cd:	cmp    %rbx,0x242a4c(%rip)        # 644420 <image_len>
  4019d4:	mov    %r11,0x10(%rsp)
  4019d9:	cmovle 0x242a3f(%rip),%rbx        # 644420 <image_len>
  4019e1:	imul   0x40(%rsp),%rax
  4019e7:	cvtsi2ss %rax,%xmm13
  4019ec:	divss  %xmm10,%xmm13
  4019f1:	cvttss2si %xmm13,%r12
  4019f6:	cvtsi2ss %r12,%xmm14
  4019fb:	ucomiss %xmm14,%xmm13
  4019ff:	jp     401a03 <Ray_Trace_Adaptively+0x1f3>
  401a01:	je     401a07 <Ray_Trace_Adaptively+0x1f7>
  401a03:	add    $0x1,%r12
  401a07:	mov    0x30(%rsp),%rbp
  401a0c:	mov    0x40(%rsp),%r14
  401a11:	imul   %r12,%r10
  401a15:	lea    0x0(%rbp,%rbp,4),%r13
  401a1a:	lea    0x200930(,%r13,8),%r15
  401a22:	add    %r10,%r14
  401a25:	cmp    %r14,0x2429fc(%rip)        # 644428 <image_len+0x8>
  401a2c:	cmovle 0x2429f4(%rip),%r14        # 644428 <image_len+0x8>
  401a34:	mov    %r10,0x18(%rsp)
  401a39:	shl    $0xb,%rbp
  401a3d:	lea    (%rsi,%r15,1),%rdi
  401a41:	mov    %r15,0x20(%rsp)
  401a46:	callq  401380 <pthread_mutex_lock@plt>
  401a4b:	mov    0x240886(%rip),%rsi        # 6422d8 <Global>
  401a52:	lea    (%rsi,%rbp,1),%rdi
  401a56:	mov    0x10(%rdi),%r12
  401a5a:	mov    0x10(%rdi),%rcx
  401a5e:	add    $0x1,%rcx
  401a62:	mov    %rcx,0x10(%rdi)
  401a66:	lea    (%rsi,%r15,1),%rdi
  401a6a:	callq  401260 <pthread_mutex_unlock@plt>
  401a6f:	cmp    %r12,(%rsp)
  401a73:	jle    401b77 <Ray_Trace_Adaptively+0x367>
  401a79:	mov    %rbp,0x28(%rsp)
  401a7e:	xchg   %ax,%ax
  401a80:	mov    %r12,%rax
  401a83:	mov    0x243716(%rip),%rdi        # 6451a0 <block_ylen>
  401a8a:	mov    0x18(%rsp),%r8
  401a8f:	cqto   
  401a91:	mov    0x243748(%rip),%r11        # 6451e0 <block_xlen>
  401a98:	mov    %r14,%r9
  401a9b:	idivq  0x8(%rsp)
  401aa0:	imul   %rdi,%rax
  401aa4:	mov    %rdx,%r12
  401aa7:	imul   %r11,%r12
  401aab:	add    0x10(%rsp),%r12
  401ab0:	lea    (%rax,%r8,1),%r13
  401ab4:	add    %r13,%rdi
  401ab7:	cmp    %r14,%rdi
  401aba:	cmovle %rdi,%r9
  401abe:	cmp    %r9,%r13
  401ac1:	jge    401b32 <Ray_Trace_Adaptively+0x322>
  401ac3:	mov    0x2436a6(%rip),%rdx        # 645170 <highest_sampling_boxlen>
  401aca:	mov    %r13,%rbp
  401acd:	add    %r12,%r11
  401ad0:	cmp    %rbx,%r11
  401ad3:	mov    %rbx,%r10
  401ad6:	mov    %r12,%r15
  401ad9:	cmovle %r11,%r10
  401add:	cmp    %r12,%r10
  401ae0:	jle    401b20 <Ray_Trace_Adaptively+0x310>
  401ae2:	nopw   0x0(%rax,%rax,1)
  401ae8:	mov    %rbp,%rsi
  401aeb:	mov    %r15,%rdi
  401aee:	callq  401580 <Ray_Trace_Adaptive_Box>
  401af3:	mov    0x2436e6(%rip),%r11        # 6451e0 <block_xlen>
  401afa:	mov    0x24366f(%rip),%rdx        # 645170 <highest_sampling_boxlen>
  401b01:	mov    %rbx,%rsi
  401b04:	add    %r12,%r11
  401b07:	add    %rdx,%r15
  401b0a:	cmp    %rbx,%r11
  401b0d:	cmovle %r11,%rsi
  401b11:	cmp    %rsi,%r15
  401b14:	jl     401ae8 <Ray_Trace_Adaptively+0x2d8>
  401b16:	mov    0x243683(%rip),%rdi        # 6451a0 <block_ylen>
  401b1d:	add    %r13,%rdi
  401b20:	add    %rdx,%rbp
  401b23:	mov    %r14,%rcx
  401b26:	cmp    %r14,%rdi
  401b29:	cmovle %rdi,%rcx
  401b2d:	cmp    %rcx,%rbp
  401b30:	jl     401ad0 <Ray_Trace_Adaptively+0x2c0>
  401b32:	mov    0x20(%rsp),%r15
  401b37:	mov    0x24079a(%rip),%rdi        # 6422d8 <Global>
  401b3e:	add    %r15,%rdi
  401b41:	callq  401380 <pthread_mutex_lock@plt>
  401b46:	mov    0x24078b(%rip),%rdi        # 6422d8 <Global>
  401b4d:	mov    0x28(%rsp),%rax
  401b52:	add    %rdi,%rax
  401b55:	add    %r15,%rdi
  401b58:	mov    0x10(%rax),%r12
  401b5c:	mov    0x10(%rax),%rdx
  401b60:	add    $0x1,%rdx
  401b64:	mov    %rdx,0x10(%rax)
  401b68:	callq  401260 <pthread_mutex_unlock@plt>
  401b6d:	cmp    %r12,(%rsp)
  401b71:	jg     401a80 <Ray_Trace_Adaptively+0x270>
  401b77:	mov    0x48(%rsp),%r8
  401b7c:	cmp    %r8,0x30(%rsp)
  401b81:	mov    0x240750(%rip),%rsi        # 6422d8 <Global>
  401b88:	mov    0x2428c1(%rip),%r11        # 644450 <num_nodes>
  401b8f:	je     401c10 <Ray_Trace_Adaptively+0x400>
  401b91:	mov    0x30(%rsp),%rax
  401b96:	mov    (%rsp),%r15
  401b9a:	add    $0x1,%rax
  401b9e:	cqto   
  401ba0:	idiv   %r11
  401ba3:	mov    %rdx,%rdi
  401ba6:	mov    %rdx,0x30(%rsp)
  401bab:	shl    $0xb,%rdi
  401baf:	add    %rsi,%rdi
  401bb2:	mov    0x10(%rdi),%rcx
  401bb6:	cmp    %rcx,%r15
  401bb9:	jg     401953 <Ray_Trace_Adaptively+0x143>
  401bbf:	mov    %r11,%r12
  401bc2:	shl    $0xb,%r12
  401bc6:	add    %rsi,%r12
  401bc9:	mov    0x10(%r12),%r8
  401bce:	test   %r8,%r8
  401bd1:	jg     401bea <Ray_Trace_Adaptively+0x3da>
  401bd3:	jmpq   401953 <Ray_Trace_Adaptively+0x143>
  401bd8:	nopl   0x0(%rax,%rax,1)
  401be0:	mov    0x10(%r12),%rbx
  401be5:	test   %rbx,%rbx
  401be8:	jle    401c06 <Ray_Trace_Adaptively+0x3f6>
  401bea:	lea    0x1(%rdx),%rax
  401bee:	cqto   
  401bf0:	idiv   %r11
  401bf3:	mov    %rdx,%r9
  401bf6:	shl    $0xb,%r9
  401bfa:	add    %rsi,%r9
  401bfd:	mov    0x10(%r9),%r10
  401c01:	cmp    %r15,%r10
  401c04:	jge    401be0 <Ray_Trace_Adaptively+0x3d0>
  401c06:	mov    %rdx,0x30(%rsp)
  401c0b:	jmpq   401953 <Ray_Trace_Adaptively+0x143>
  401c10:	lea    (%r11,%r11,4),%r9
  401c14:	lea    0x200930(%rsi,%r9,8),%rdi
  401c1c:	callq  401380 <pthread_mutex_lock@plt>
  401c21:	mov    0x242828(%rip),%rbx        # 644450 <num_nodes>
  401c28:	mov    0x2406a9(%rip),%r10        # 6422d8 <Global>
  401c2f:	mov    %rbx,%rbp
  401c32:	lea    (%rbx,%rbx,4),%r14
  401c36:	shl    $0xb,%rbp
  401c3a:	add    %r10,%rbp
  401c3d:	lea    0x200930(%r10,%r14,8),%rdi
  401c45:	mov    0x10(%rbp),%r13
  401c49:	sub    $0x1,%r13
  401c4d:	mov    %r13,0x10(%rbp)
  401c51:	callq  401260 <pthread_mutex_unlock@plt>
  401c56:	mov    0x2427f3(%rip),%r11        # 644450 <num_nodes>
  401c5d:	mov    0x240674(%rip),%rsi        # 6422d8 <Global>
  401c64:	jmpq   401b91 <Ray_Trace_Adaptively+0x381>
  401c69:	add    $0x58,%rsp
  401c6d:	pop    %rbx
  401c6e:	pop    %rbp
  401c6f:	pop    %r12
  401c71:	pop    %r13
  401c73:	pop    %r14
  401c75:	pop    %r15
  401c77:	retq   
  401c78:	nopl   0x0(%rax,%rax,1)

0000000000401c80 <Ray_Trace_Non_Adaptively>:
  401c80:	push   %r15
  401c82:	pxor   %xmm0,%xmm0
  401c86:	push   %r14
  401c88:	pxor   %xmm1,%xmm1
  401c8c:	push   %r13
  401c8e:	push   %r12
  401c90:	push   %rbp
  401c91:	push   %rbx
  401c92:	pxor   %xmm3,%xmm3
  401c96:	sub    $0x68,%rsp
  401c9a:	cvtsi2ssq 0x24277d(%rip),%xmm0        # 644420 <image_len>
  401ca3:	mov    %rdi,0x58(%rsp)
  401ca8:	cvtsi2ssq 0x2427af(%rip),%xmm1        # 644460 <image_section>
  401cb1:	divss  %xmm1,%xmm0
  401cb5:	cvttss2si %xmm0,%rax
  401cba:	cvtsi2ss %rax,%xmm3
  401cbf:	mov    %rax,0x48(%rsp)
  401cc4:	ucomiss %xmm3,%xmm0
  401cc7:	jp     401ccb <Ray_Trace_Non_Adaptively+0x4b>
  401cc9:	je     401cdc <Ray_Trace_Non_Adaptively+0x5c>
  401ccb:	addq   $0x1,0x48(%rsp)
  401cd1:	pxor   %xmm3,%xmm3
  401cd5:	cvtsi2ssq 0x48(%rsp),%xmm3
  401cdc:	pxor   %xmm2,%xmm2
  401ce0:	pxor   %xmm4,%xmm4
  401ce4:	pxor   %xmm5,%xmm5
  401ce8:	cvtsi2ssq 0x242737(%rip),%xmm2        # 644428 <image_len+0x8>
  401cf1:	cvtsi2ssq 0x24276e(%rip),%xmm4        # 644468 <image_section+0x8>
  401cfa:	divss  %xmm4,%xmm2
  401cfe:	cvttss2si %xmm2,%rdx
  401d03:	cvtsi2ss %rdx,%xmm5
  401d08:	mov    %rdx,0x50(%rsp)
  401d0d:	ucomiss %xmm5,%xmm2
  401d10:	jp     401d14 <Ray_Trace_Non_Adaptively+0x94>
  401d12:	je     401d25 <Ray_Trace_Non_Adaptively+0xa5>
  401d14:	addq   $0x1,0x50(%rsp)
  401d1a:	pxor   %xmm5,%xmm5
  401d1e:	cvtsi2ssq 0x50(%rsp),%xmm5
  401d25:	pxor   %xmm6,%xmm6
  401d29:	pxor   %xmm7,%xmm7
  401d2d:	cvtsi2ssq 0x2434aa(%rip),%xmm6        # 6451e0 <block_xlen>
  401d36:	divss  %xmm6,%xmm3
  401d3a:	cvttss2si %xmm3,%rcx
  401d3f:	cvtsi2ss %rcx,%xmm7
  401d44:	mov    %rcx,0x18(%rsp)
  401d49:	ucomiss %xmm7,%xmm3
  401d4c:	jp     401d50 <Ray_Trace_Non_Adaptively+0xd0>
  401d4e:	je     401d56 <Ray_Trace_Non_Adaptively+0xd6>
  401d50:	addq   $0x1,0x18(%rsp)
  401d56:	pxor   %xmm8,%xmm8
  401d5b:	pxor   %xmm9,%xmm9
  401d60:	cvtsi2ssq 0x243437(%rip),%xmm8        # 6451a0 <block_ylen>
  401d69:	divss  %xmm8,%xmm5
  401d6e:	cvttss2si %xmm5,%rbx
  401d73:	cvtsi2ss %rbx,%xmm9
  401d78:	ucomiss %xmm9,%xmm5
  401d7c:	jp     401d80 <Ray_Trace_Non_Adaptively+0x100>
  401d7e:	je     401d84 <Ray_Trace_Non_Adaptively+0x104>
  401d80:	add    $0x1,%rbx
  401d84:	imul   0x18(%rsp),%rbx
  401d8a:	mov    0x58(%rsp),%rdi
  401d8f:	mov    0x240542(%rip),%rcx        # 6422d8 <Global>
  401d96:	mov    0x2426b3(%rip),%r11        # 644450 <num_nodes>
  401d9d:	mov    %rdi,%rbp
  401da0:	mov    %rdi,0x40(%rsp)
  401da5:	shl    $0xb,%rbp
  401da9:	add    %rcx,%rbp
  401dac:	mov    %rbx,0x10(%rsp)
  401db1:	movq   $0x0,0x10(%rbp)
  401db9:	shl    $0xb,%r11
  401dbd:	lea    (%rcx,%r11,1),%r8
  401dc1:	mov    0x10(%r8),%r9
  401dc5:	test   %r9,%r9
  401dc8:	jle    4020a0 <Ray_Trace_Non_Adaptively+0x420>
  401dce:	mov    0x40(%rsp),%rax
  401dd3:	mov    0x48(%rsp),%rbx
  401dd8:	mov    0x40(%rsp),%rbp
  401ddd:	mov    0x50(%rsp),%r14
  401de2:	cqto   
  401de4:	idivq  0x242675(%rip)        # 644460 <image_section>
  401deb:	lea    0x0(%rbp,%rbp,4),%r10
  401df0:	lea    0x200930(,%r10,8),%r13
  401df8:	lea    (%rcx,%r13,1),%rdi
  401dfc:	mov    %r13,0x30(%rsp)
  401e01:	imul   %rbx,%rdx
  401e05:	add    %rdx,%rbx
  401e08:	cmp    %rbx,0x242611(%rip)        # 644420 <image_len>
  401e0f:	mov    %rdx,0x20(%rsp)
  401e14:	cmovle 0x242604(%rip),%rbx        # 644420 <image_len>
  401e1c:	imul   %r14,%rax
  401e20:	add    %rax,%r14
  401e23:	cmp    %r14,0x2425fe(%rip)        # 644428 <image_len+0x8>
  401e2a:	mov    %rax,0x28(%rsp)
  401e2f:	cmovle 0x2425f1(%rip),%r14        # 644428 <image_len+0x8>
  401e37:	shl    $0xb,%rbp
  401e3b:	callq  401380 <pthread_mutex_lock@plt>
  401e40:	mov    0x240491(%rip),%rsi        # 6422d8 <Global>
  401e47:	lea    (%rsi,%rbp,1),%r11
  401e4b:	lea    (%rsi,%r13,1),%rdi
  401e4f:	mov    0x10(%r11),%r12
  401e53:	lea    0x1(%r12),%rcx
  401e58:	mov    %rcx,0x10(%r11)
  401e5c:	callq  401260 <pthread_mutex_unlock@plt>
  401e61:	cmp    0x10(%rsp),%r12
  401e66:	jge    401fb4 <Ray_Trace_Non_Adaptively+0x334>
  401e6c:	mov    %rbp,0x38(%rsp)
  401e71:	nopl   0x0(%rax)
  401e78:	mov    %r12,%rax
  401e7b:	mov    0x24331e(%rip),%r8        # 6451a0 <block_ylen>
  401e82:	mov    0x28(%rsp),%r9
  401e87:	cqto   
  401e89:	mov    0x243350(%rip),%rdi        # 6451e0 <block_xlen>
  401e90:	mov    %r14,%r10
  401e93:	idivq  0x18(%rsp)
  401e98:	imul   %r8,%rax
  401e9c:	mov    %rdx,%r12
  401e9f:	imul   %rdi,%r12
  401ea3:	add    0x20(%rsp),%r12
  401ea8:	lea    (%rax,%r9,1),%r13
  401eac:	lea    (%r8,%r13,1),%rax
  401eb0:	mov    %r13,%rbp
  401eb3:	lea    (%rdi,%r12,1),%r11
  401eb7:	cmp    %r14,%rax
  401eba:	cmovle %rax,%r10
  401ebe:	cmp    %r10,%r13
  401ec1:	jge    401f71 <Ray_Trace_Non_Adaptively+0x2f1>
  401ec7:	nopw   0x0(%rax,%rax,1)
  401ed0:	cmp    %rbx,%r11
  401ed3:	mov    %rbx,%rsi
  401ed6:	cmovle %r11,%rsi
  401eda:	cmp    %r12,%rsi
  401edd:	jle    401f5a <Ray_Trace_Non_Adaptively+0x2da>
  401edf:	pxor   %xmm10,%xmm10
  401ee4:	mov    %r12,%r15
  401ee7:	pxor   %xmm11,%xmm11
  401eec:	cvtsi2ss %rbp,%xmm10
  401ef1:	cvtss2sd %xmm10,%xmm11
  401ef6:	movsd  %xmm11,0x8(%rsp)
  401efd:	nopl   (%rax)
  401f00:	pxor   %xmm12,%xmm12
  401f05:	mov    0x242514(%rip),%rdi        # 644420 <image_len>
  401f0c:	pxor   %xmm0,%xmm0
  401f10:	movsd  0x8(%rsp),%xmm1
  401f16:	cvtsi2ss %r15,%xmm12
  401f1b:	imul   %rbp,%rdi
  401f1f:	add    %r15,%rdi
  401f22:	add    0x2403b7(%rip),%rdi        # 6422e0 <image_address>
  401f29:	add    $0x1,%r15
  401f2d:	cvtss2sd %xmm12,%xmm0
  401f32:	callq  4092f0 <Trace_Ray>
  401f37:	mov    0x2432a2(%rip),%r11        # 6451e0 <block_xlen>
  401f3e:	mov    %rbx,%rcx
  401f41:	add    %r12,%r11
  401f44:	cmp    %rbx,%r11
  401f47:	cmovle %r11,%rcx
  401f4b:	cmp    %rcx,%r15
  401f4e:	jl     401f00 <Ray_Trace_Non_Adaptively+0x280>
  401f50:	mov    0x243249(%rip),%rax        # 6451a0 <block_ylen>
  401f57:	add    %r13,%rax
  401f5a:	add    $0x1,%rbp
  401f5e:	mov    %r14,%rdx
  401f61:	cmp    %r14,%rax
  401f64:	cmovle %rax,%rdx
  401f68:	cmp    %rdx,%rbp
  401f6b:	jl     401ed0 <Ray_Trace_Non_Adaptively+0x250>
  401f71:	mov    0x30(%rsp),%rbp
  401f76:	mov    0x24035b(%rip),%rdi        # 6422d8 <Global>
  401f7d:	add    %rbp,%rdi
  401f80:	callq  401380 <pthread_mutex_lock@plt>
  401f85:	mov    0x24034c(%rip),%rdi        # 6422d8 <Global>
  401f8c:	mov    0x38(%rsp),%r8
  401f91:	add    %rdi,%r8
  401f94:	add    %rbp,%rdi
  401f97:	mov    0x10(%r8),%r12
  401f9b:	lea    0x1(%r12),%r9
  401fa0:	mov    %r9,0x10(%r8)
  401fa4:	callq  401260 <pthread_mutex_unlock@plt>
  401fa9:	cmp    0x10(%rsp),%r12
  401fae:	jl     401e78 <Ray_Trace_Non_Adaptively+0x1f8>
  401fb4:	mov    0x58(%rsp),%rdi
  401fb9:	cmp    %rdi,0x40(%rsp)
  401fbe:	mov    0x240313(%rip),%rcx        # 6422d8 <Global>
  401fc5:	mov    0x242484(%rip),%r11        # 644450 <num_nodes>
  401fcc:	je     402047 <Ray_Trace_Non_Adaptively+0x3c7>
  401fce:	mov    0x40(%rsp),%rax
  401fd3:	mov    0x10(%rsp),%r12
  401fd8:	add    $0x1,%rax
  401fdc:	cqto   
  401fde:	idiv   %r11
  401fe1:	mov    %rdx,%rbp
  401fe4:	mov    %rdx,0x40(%rsp)
  401fe9:	shl    $0xb,%rbp
  401fed:	add    %rcx,%rbp
  401ff0:	mov    0x10(%rbp),%r8
  401ff4:	cmp    %r8,%r12
  401ff7:	jg     401db9 <Ray_Trace_Non_Adaptively+0x139>
  401ffd:	mov    %r11,%r9
  402000:	shl    $0xb,%r9
  402004:	add    %rcx,%r9
  402007:	mov    0x10(%r9),%rdi
  40200b:	test   %rdi,%rdi
  40200e:	jg     402021 <Ray_Trace_Non_Adaptively+0x3a1>
  402010:	jmpq   401db9 <Ray_Trace_Non_Adaptively+0x139>
  402015:	nopl   (%rax)
  402018:	mov    0x10(%r9),%rbx
  40201c:	test   %rbx,%rbx
  40201f:	jle    40203d <Ray_Trace_Non_Adaptively+0x3bd>
  402021:	lea    0x1(%rdx),%rax
  402025:	cqto   
  402027:	idiv   %r11
  40202a:	mov    %rdx,%r10
  40202d:	shl    $0xb,%r10
  402031:	add    %rcx,%r10
  402034:	mov    0x10(%r10),%rsi
  402038:	cmp    %r12,%rsi
  40203b:	jge    402018 <Ray_Trace_Non_Adaptively+0x398>
  40203d:	mov    %rdx,0x40(%rsp)
  402042:	jmpq   401db9 <Ray_Trace_Non_Adaptively+0x139>
  402047:	lea    (%r11,%r11,4),%r10
  40204b:	lea    0x200930(%rcx,%r10,8),%rdi
  402053:	callq  401380 <pthread_mutex_lock@plt>
  402058:	mov    0x2423f1(%rip),%rbx        # 644450 <num_nodes>
  40205f:	mov    0x240272(%rip),%rsi        # 6422d8 <Global>
  402066:	mov    %rbx,%r13
  402069:	lea    (%rbx,%rbx,4),%r15
  40206d:	shl    $0xb,%r13
  402071:	add    %rsi,%r13
  402074:	lea    0x200930(%rsi,%r15,8),%rdi
  40207c:	mov    0x10(%r13),%r14
  402080:	sub    $0x1,%r14
  402084:	mov    %r14,0x10(%r13)
  402088:	callq  401260 <pthread_mutex_unlock@plt>
  40208d:	mov    0x2423bc(%rip),%r11        # 644450 <num_nodes>
  402094:	mov    0x24023d(%rip),%rcx        # 6422d8 <Global>
  40209b:	jmpq   401fce <Ray_Trace_Non_Adaptively+0x34e>
  4020a0:	add    $0x68,%rsp
  4020a4:	pop    %rbx
  4020a5:	pop    %rbp
  4020a6:	pop    %r12
  4020a8:	pop    %r13
  4020aa:	pop    %r14
  4020ac:	pop    %r15
  4020ae:	retq   
  4020af:	nop

00000000004020b0 <Ray_Trace_Fast_Non_Adaptively>:
  4020b0:	mov    0x242391(%rip),%r11        # 644448 <num_blocks>
  4020b7:	test   %r11,%r11
  4020ba:	jle    402229 <Ray_Trace_Fast_Non_Adaptively+0x179>
  4020c0:	push   %r15
  4020c2:	push   %r14
  4020c4:	mov    %rdi,%r14
  4020c7:	push   %r13
  4020c9:	push   %r12
  4020cb:	xor    %r13d,%r13d
  4020ce:	push   %rbp
  4020cf:	push   %rbx
  4020d0:	sub    $0x18,%rsp
  4020d4:	mov    0x2430c5(%rip),%rdi        # 6451a0 <block_ylen>
  4020db:	mov    0x2430fe(%rip),%r9        # 6451e0 <block_xlen>
  4020e2:	nopw   0x0(%rax,%rax,1)
  4020e8:	lea    (%r14,%r13,1),%rax
  4020ec:	cqto   
  4020ee:	idivq  0x2401bb(%rip)        # 6422b0 <num_xblocks>
  4020f5:	imul   %rdi,%rax
  4020f9:	imul   %r9,%rdx
  4020fd:	lea    (%rax,%rdi,1),%rsi
  402101:	mov    %rax,%r12
  402104:	mov    %rdx,%rbp
  402107:	cmp    %rsi,%rax
  40210a:	jge    4021fb <Ray_Trace_Fast_Non_Adaptively+0x14b>
  402110:	cmp    0x242311(%rip),%rax        # 644428 <image_len+0x8>
  402117:	mov    %rax,%r15
  40211a:	lea    (%r9,%rdx,1),%r10
  40211e:	jge    4021fb <Ray_Trace_Fast_Non_Adaptively+0x14b>
  402124:	nopl   0x0(%rax)
  402128:	cmp    %r10,%rbp
  40212b:	jge    402220 <Ray_Trace_Fast_Non_Adaptively+0x170>
  402131:	cmp    0x2422e8(%rip),%rbp        # 644420 <image_len>
  402138:	jge    402220 <Ray_Trace_Fast_Non_Adaptively+0x170>
  40213e:	pxor   %xmm0,%xmm0
  402142:	mov    %rbp,%rbx
  402145:	pxor   %xmm2,%xmm2
  402149:	cvtsi2ss %r15,%xmm0
  40214e:	cvtss2sd %xmm0,%xmm2
  402152:	movsd  %xmm2,0x8(%rsp)
  402158:	jmp    402169 <Ray_Trace_Fast_Non_Adaptively+0xb9>
  40215a:	nopw   0x0(%rax,%rax,1)
  402160:	cmp    %rbx,0x2422b9(%rip)        # 644420 <image_len>
  402167:	jle    4021d4 <Ray_Trace_Fast_Non_Adaptively+0x124>
  402169:	mov    0x240180(%rip),%rcx        # 6422f0 <mask_image_len>
  402170:	pxor   %xmm1,%xmm1
  402174:	pxor   %xmm0,%xmm0
  402178:	imul   %r15,%rcx
  40217c:	cvtsi2ss %rbx,%xmm1
  402181:	add    %rbx,%rcx
  402184:	add    0x240115(%rip),%rcx        # 6422a0 <mask_image_address>
  40218b:	addb   $0x80,(%rcx)
  40218e:	mov    0x24228b(%rip),%rdi        # 644420 <image_len>
  402195:	imul   %r15,%rdi
  402199:	cvtss2sd %xmm1,%xmm0
  40219d:	add    %rbx,%rdi
  4021a0:	add    0x240139(%rip),%rdi        # 6422e0 <image_address>
  4021a7:	movsd  0x8(%rsp),%xmm1
  4021ad:	callq  4092f0 <Trace_Ray>
  4021b2:	mov    0x243027(%rip),%r9        # 6451e0 <block_xlen>
  4021b9:	mov    0x243018(%rip),%r8        # 6451d8 <lowest_volume_boxlen>
  4021c0:	addq   $0x1,0x240088(%rip)        # 642250 <num_rays_traced>
  4021c8:	lea    (%r9,%rbp,1),%r10
  4021cc:	add    %r8,%rbx
  4021cf:	cmp    %rbx,%r10
  4021d2:	jg     402160 <Ray_Trace_Fast_Non_Adaptively+0xb0>
  4021d4:	mov    0x242fc5(%rip),%rdi        # 6451a0 <block_ylen>
  4021db:	lea    (%r12,%rdi,1),%rsi
  4021df:	add    %r8,%r15
  4021e2:	cmp    %r15,%rsi
  4021e5:	jle    4021f4 <Ray_Trace_Fast_Non_Adaptively+0x144>
  4021e7:	cmp    %r15,0x24223a(%rip)        # 644428 <image_len+0x8>
  4021ee:	jg     402128 <Ray_Trace_Fast_Non_Adaptively+0x78>
  4021f4:	mov    0x24224d(%rip),%r11        # 644448 <num_blocks>
  4021fb:	add    0x24224e(%rip),%r13        # 644450 <num_nodes>
  402202:	cmp    %r11,%r13
  402205:	jl     4020e8 <Ray_Trace_Fast_Non_Adaptively+0x38>
  40220b:	add    $0x18,%rsp
  40220f:	pop    %rbx
  402210:	pop    %rbp
  402211:	pop    %r12
  402213:	pop    %r13
  402215:	pop    %r14
  402217:	pop    %r15
  402219:	retq   
  40221a:	nopw   0x0(%rax,%rax,1)
  402220:	mov    0x242fb1(%rip),%r8        # 6451d8 <lowest_volume_boxlen>
  402227:	jmp    4021df <Ray_Trace_Fast_Non_Adaptively+0x12f>
  402229:	repz retq 
  40222b:	nopl   0x0(%rax,%rax,1)

0000000000402230 <Interpolate_Recursive_Box>:
  402230:	pxor   %xmm0,%xmm0
  402234:	push   %r15
  402236:	push   %r14
  402238:	push   %r13
  40223a:	mov    %rsi,%r10
  40223d:	push   %r12
  40223f:	push   %rbp
  402240:	mov    %rdx,%r12
  402243:	cvtsi2ss %rdx,%xmm0
  402248:	push   %rbx
  402249:	lea    (%r12,%rsi,1),%rax
  40224d:	mov    %rdx,%rbp
  402250:	add    %rdi,%rdx
  402253:	mov    %rdi,%rbx
  402256:	sar    %rbp
  402259:	sub    $0x18,%rsp
  40225d:	mov    0x2421bc(%rip),%rcx        # 644420 <image_len>
  402264:	mov    %rdx,%rdi
  402267:	mov    %rsi,0x8(%rsp)
  40226c:	mov    0x2421b5(%rip),%rsi        # 644428 <image_len+0x8>
  402273:	mov    %r10,%r8
  402276:	movss  0x16b7e(%rip),%xmm6        # 418dfc <__dso_handle+0x34>
  40227e:	cmp    %rcx,%rdx
  402281:	mov    0x240058(%rip),%rdx        # 6422e0 <image_address>
  402288:	cmovge %rbx,%rdi
  40228c:	cmp    %rsi,%rax
  40228f:	cmovge %r10,%rax
  402293:	movaps %xmm6,%xmm7
  402296:	imul   %rcx,%r8
  40229a:	lea    (%rdx,%rbx,1),%r9
  40229e:	imul   %rcx,%rax
  4022a2:	add    %rdx,%r8
  4022a5:	add    %rdi,%rdx
  4022a8:	test   %r12,%r12
  4022ab:	divss  %xmm0,%xmm7
  4022af:	movzbl (%r8,%rbx,1),%r11d
  4022b4:	movzbl (%r8,%rdi,1),%r13d
  4022b9:	movzbl (%r9,%rax,1),%r14d
  4022be:	movzbl (%rdx,%rax,1),%r15d
  4022c3:	js     402410 <Interpolate_Recursive_Box+0x1e0>
  4022c9:	cmp    %r10,%rsi
  4022cc:	jle    402410 <Interpolate_Recursive_Box+0x1e0>
  4022d2:	mov    %rbp,%r9
  4022d5:	mov    %r10,%rsi
  4022d8:	xor    %r10d,%r10d
  4022db:	sub    %rbx,%r9
  4022de:	xchg   %ax,%ax
  4022e0:	movaps %xmm6,%xmm5
  4022e3:	cmp    %rcx,%rbx
  4022e6:	pxor   %xmm4,%xmm4
  4022ea:	cvtsi2ss %r10,%xmm4
  4022ef:	mulss  %xmm7,%xmm4
  4022f3:	subss  %xmm4,%xmm5
  4022f7:	jge    4023f0 <Interpolate_Recursive_Box+0x1c0>
  4022fd:	mov    %rbx,%rax
  402300:	jmp    40231b <Interpolate_Recursive_Box+0xeb>
  402302:	nopw   0x0(%rax,%rax,1)
  402308:	mov    0x242111(%rip),%rcx        # 644420 <image_len>
  40230f:	add    %rbp,%rax
  402312:	cmp    %rax,%rcx
  402315:	jle    4023f0 <Interpolate_Recursive_Box+0x1c0>
  40231b:	mov    0x23ffce(%rip),%rdx        # 6422f0 <mask_image_len>
  402322:	mov    0x23ff77(%rip),%rdi        # 6422a0 <mask_image_address>
  402329:	mov    %rax,%r8
  40232c:	sub    %rbx,%r8
  40232f:	imul   %rsi,%rdx
  402333:	add    %rax,%rdi
  402336:	cmpb   $0x0,(%rdi,%rdx,1)
  40233a:	jne    4023e3 <Interpolate_Recursive_Box+0x1b3>
  402340:	pxor   %xmm8,%xmm8
  402345:	movaps %xmm6,%xmm1
  402348:	pxor   %xmm3,%xmm3
  40234c:	pxor   %xmm2,%xmm2
  402350:	cvtsi2ss %r8,%xmm8
  402355:	imul   %rsi,%rcx
  402359:	mov    0x23ff80(%rip),%r8        # 6422e0 <image_address>
  402360:	cvtsi2ss %r11,%xmm3
  402365:	cvtsi2ss %r13,%xmm2
  40236a:	add    %rax,%r8
  40236d:	pxor   %xmm10,%xmm10
  402372:	pxor   %xmm11,%xmm11
  402377:	cvtsi2ss %r14,%xmm10
  40237c:	cvtsi2ss %r15,%xmm11
  402381:	mulss  %xmm7,%xmm8
  402386:	subss  %xmm8,%xmm1
  40238b:	mulss  %xmm8,%xmm2
  402390:	mulss  %xmm1,%xmm3
  402394:	mulss  %xmm5,%xmm2
  402398:	mulss  %xmm10,%xmm1
  40239d:	mulss  %xmm11,%xmm8
  4023a2:	movaps %xmm3,%xmm9
  4023a6:	mulss  %xmm5,%xmm9
  4023ab:	mulss  %xmm4,%xmm1
  4023af:	mulss  %xmm4,%xmm8
  4023b4:	addss  %xmm9,%xmm2
  4023b9:	addss  %xmm2,%xmm1
  4023bd:	addss  %xmm1,%xmm8
  4023c2:	cvttss2si %xmm8,%rdx
  4023c7:	mov    %dl,(%r8,%rcx,1)
  4023cb:	mov    0x23ff1e(%rip),%rcx        # 6422f0 <mask_image_len>
  4023d2:	imul   %rsi,%rcx
  4023d6:	add    %rax,%rcx
  4023d9:	add    0x23fec0(%rip),%rcx        # 6422a0 <mask_image_address>
  4023e0:	addb   $0x8,(%rcx)
  4023e3:	lea    (%r9,%rax,1),%rdi
  4023e7:	cmp    %rdi,%r12
  4023ea:	jge    402308 <Interpolate_Recursive_Box+0xd8>
  4023f0:	add    %rbp,%r10
  4023f3:	cmp    %r10,%r12
  4023f6:	jl     402410 <Interpolate_Recursive_Box+0x1e0>
  4023f8:	add    %rbp,%rsi
  4023fb:	cmp    %rsi,0x242026(%rip)        # 644428 <image_len+0x8>
  402402:	jle    402410 <Interpolate_Recursive_Box+0x1e0>
  402404:	mov    0x242015(%rip),%rcx        # 644420 <image_len>
  40240b:	jmpq   4022e0 <Interpolate_Recursive_Box+0xb0>
  402410:	mov    0x8(%rsp),%r14
  402415:	cmp    $0x1,%rbp
  402419:	mov    %r14,%r15
  40241c:	jle    40245d <Interpolate_Recursive_Box+0x22d>
  40241e:	cmp    0x242003(%rip),%r14        # 644428 <image_len+0x8>
  402425:	jge    40245d <Interpolate_Recursive_Box+0x22d>
  402427:	mov    %rbx,%r13
  40242a:	cmp    0x241fef(%rip),%r13        # 644420 <image_len>
  402431:	jge    40244f <Interpolate_Recursive_Box+0x21f>
  402433:	mov    %r13,%rdi
  402436:	mov    %rbp,%rdx
  402439:	add    %rbp,%r13
  40243c:	mov    %r14,%rsi
  40243f:	callq  402230 <Interpolate_Recursive_Box>
  402444:	mov    %r13,%r11
  402447:	sub    %rbx,%r11
  40244a:	cmp    %r11,%r12
  40244d:	jg     40242a <Interpolate_Recursive_Box+0x1fa>
  40244f:	add    %rbp,%r14
  402452:	mov    %r14,%rsi
  402455:	sub    %r15,%rsi
  402458:	cmp    %rsi,%r12
  40245b:	jg     40241e <Interpolate_Recursive_Box+0x1ee>
  40245d:	add    $0x18,%rsp
  402461:	pop    %rbx
  402462:	pop    %rbp
  402463:	pop    %r12
  402465:	pop    %r13
  402467:	pop    %r14
  402469:	pop    %r15
  40246b:	retq   
  40246c:	nopl   0x0(%rax)

0000000000402470 <Interpolate_Recursively>:
  402470:	mov    0x241fd1(%rip),%r9        # 644448 <num_blocks>
  402477:	test   %r9,%r9
  40247a:	jle    402579 <Interpolate_Recursively+0x109>
  402480:	push   %r15
  402482:	push   %r14
  402484:	mov    %rdi,%r15
  402487:	push   %r13
  402489:	push   %r12
  40248b:	xor    %r14d,%r14d
  40248e:	push   %rbp
  40248f:	push   %rbx
  402490:	sub    $0x8,%rsp
  402494:	mov    0x242d05(%rip),%rdi        # 6451a0 <block_ylen>
  40249b:	mov    0x242d3e(%rip),%rcx        # 6451e0 <block_xlen>
  4024a2:	nopw   0x0(%rax,%rax,1)
  4024a8:	lea    (%r15,%r14,1),%rax
  4024ac:	cqto   
  4024ae:	idivq  0x23fdfb(%rip)        # 6422b0 <num_xblocks>
  4024b5:	imul   %rdi,%rax
  4024b9:	imul   %rcx,%rdx
  4024bd:	lea    (%rax,%rdi,1),%rsi
  4024c1:	mov    %rax,%r13
  4024c4:	mov    %rdx,%r12
  4024c7:	cmp    %rsi,%rax
  4024ca:	jge    40255a <Interpolate_Recursively+0xea>
  4024d0:	cmp    0x241f51(%rip),%rax        # 644428 <image_len+0x8>
  4024d7:	jge    40255a <Interpolate_Recursively+0xea>
  4024dd:	mov    0x242c8c(%rip),%rdx        # 645170 <highest_sampling_boxlen>
  4024e4:	lea    (%rcx,%r12,1),%r8
  4024e8:	mov    %rax,%rbp
  4024eb:	nopl   0x0(%rax,%rax,1)
  4024f0:	cmp    %r8,%r12
  4024f3:	jge    402542 <Interpolate_Recursively+0xd2>
  4024f5:	cmp    0x241f24(%rip),%r12        # 644420 <image_len>
  4024fc:	mov    %r12,%rbx
  4024ff:	jl     402511 <Interpolate_Recursively+0xa1>
  402501:	jmp    402542 <Interpolate_Recursively+0xd2>
  402503:	nopl   0x0(%rax,%rax,1)
  402508:	cmp    %rbx,0x241f11(%rip)        # 644420 <image_len>
  40250f:	jle    402536 <Interpolate_Recursively+0xc6>
  402511:	mov    %rbx,%rdi
  402514:	mov    %rbp,%rsi
  402517:	callq  402230 <Interpolate_Recursive_Box>
  40251c:	mov    0x242cbd(%rip),%rcx        # 6451e0 <block_xlen>
  402523:	mov    0x242c46(%rip),%rdx        # 645170 <highest_sampling_boxlen>
  40252a:	lea    (%rcx,%r12,1),%r8
  40252e:	add    %rdx,%rbx
  402531:	cmp    %rbx,%r8
  402534:	jg     402508 <Interpolate_Recursively+0x98>
  402536:	mov    0x242c63(%rip),%rdi        # 6451a0 <block_ylen>
  40253d:	lea    0x0(%r13,%rdi,1),%rsi
  402542:	add    %rdx,%rbp
  402545:	cmp    %rbp,%rsi
  402548:	jle    402553 <Interpolate_Recursively+0xe3>
  40254a:	cmp    %rbp,0x241ed7(%rip)        # 644428 <image_len+0x8>
  402551:	jg     4024f0 <Interpolate_Recursively+0x80>
  402553:	mov    0x241eee(%rip),%r9        # 644448 <num_blocks>
  40255a:	add    0x241eef(%rip),%r14        # 644450 <num_nodes>
  402561:	cmp    %r9,%r14
  402564:	jl     4024a8 <Interpolate_Recursively+0x38>
  40256a:	add    $0x8,%rsp
  40256e:	pop    %rbx
  40256f:	pop    %rbp
  402570:	pop    %r12
  402572:	pop    %r13
  402574:	pop    %r14
  402576:	pop    %r15
  402578:	retq   
  402579:	repz retq 
  40257b:	nopl   0x0(%rax,%rax,1)

0000000000402580 <Ray_Trace>:
  402580:	push   %r15
  402582:	push   %r14
  402584:	mov    %rdi,%r14
  402587:	push   %r13
  402589:	push   %r12
  40258b:	push   %rbp
  40258c:	push   %rbx
  40258d:	pxor   %xmm12,%xmm12
  402592:	sub    $0x38,%rsp
  402596:	movss  0x246ca2(%rip),%xmm0        # 649240 <uout_invvertex>
  40259e:	movss  0x246ca5(%rip),%xmm10        # 64924c <uout_invvertex+0xc>
  4025a7:	subss  %xmm0,%xmm10
  4025ac:	movss  0x246c90(%rip),%xmm1        # 649244 <uout_invvertex+0x4>
  4025b4:	movss  0x246c8b(%rip),%xmm11        # 649248 <uout_invvertex+0x8>
  4025bd:	movss  0x246c93(%rip),%xmm7        # 649258 <uout_invvertex+0x18>
  4025c5:	movss  0x246ca3(%rip),%xmm4        # 649270 <uout_invvertex+0x30>
  4025cd:	subss  %xmm0,%xmm7
  4025d1:	movss  0x246c76(%rip),%xmm9        # 649250 <uout_invvertex+0x10>
  4025da:	subss  %xmm0,%xmm4
  4025de:	movss  0x246c76(%rip),%xmm6        # 64925c <uout_invvertex+0x1c>
  4025e6:	subss  %xmm1,%xmm9
  4025eb:	movss  0x246c81(%rip),%xmm3        # 649274 <uout_invvertex+0x34>
  4025f3:	subss  %xmm1,%xmm6
  4025f7:	movss  0x246c54(%rip),%xmm8        # 649254 <uout_invvertex+0x14>
  402600:	subss  %xmm1,%xmm3
  402604:	movss  0x246c54(%rip),%xmm5        # 649260 <uout_invvertex+0x20>
  40260c:	subss  %xmm11,%xmm8
  402611:	movss  0x246c5f(%rip),%xmm2        # 649278 <uout_invvertex+0x38>
  402619:	subss  %xmm11,%xmm5
  40261e:	subss  %xmm11,%xmm2
  402623:	movss  %xmm10,0x23fc34(%rip)        # 642260 <invjacobian>
  40262c:	ucomiss %xmm12,%xmm10
  402630:	movss  %xmm7,0x23fc34(%rip)        # 64226c <invjacobian+0xc>
  402638:	movaps %xmm10,%xmm13
  40263c:	movss  %xmm4,0x23fc34(%rip)        # 642278 <invjacobian+0x18>
  402644:	movss  %xmm9,0x23fc17(%rip)        # 642264 <invjacobian+0x4>
  40264d:	movss  %xmm6,0x23fc1b(%rip)        # 642270 <invjacobian+0x10>
  402655:	movss  %xmm3,0x23fc1f(%rip)        # 64227c <invjacobian+0x1c>
  40265d:	movss  %xmm8,0x23fc02(%rip)        # 642268 <invjacobian+0x8>
  402666:	movss  %xmm5,0x23fc06(%rip)        # 642274 <invjacobian+0x14>
  40266e:	movss  %xmm2,0x23fc0a(%rip)        # 642280 <invjacobian+0x20>
  402676:	ja     402680 <Ray_Trace+0x100>
  402678:	xorps  0x16780(%rip),%xmm13        # 418e00 <__dso_handle+0x38>
  402680:	pxor   %xmm14,%xmm14
  402685:	movsd  0x16782(%rip),%xmm15        # 418e10 <__dso_handle+0x48>
  40268e:	cvtss2sd %xmm13,%xmm14
  402693:	ucomisd %xmm15,%xmm14
  402698:	jbe    4026af <Ray_Trace+0x12f>
  40269a:	movss  0x1675a(%rip),%xmm0        # 418dfc <__dso_handle+0x34>
  4026a2:	divss  %xmm10,%xmm0
  4026a7:	movss  %xmm0,0x23fb71(%rip)        # 642220 <invinvjacobian>
  4026af:	ucomiss %xmm12,%xmm9
  4026b3:	movaps %xmm9,%xmm1
  4026b7:	ja     4026c0 <Ray_Trace+0x140>
  4026b9:	xorps  0x16740(%rip),%xmm1        # 418e00 <__dso_handle+0x38>
  4026c0:	pxor   %xmm11,%xmm11
  4026c5:	cvtss2sd %xmm1,%xmm11
  4026ca:	ucomisd %xmm15,%xmm11
  4026cf:	jbe    4026e8 <Ray_Trace+0x168>
  4026d1:	movss  0x16722(%rip),%xmm13        # 418dfc <__dso_handle+0x34>
  4026da:	divss  %xmm9,%xmm13
  4026df:	movss  %xmm13,0x23fb3c(%rip)        # 642224 <invinvjacobian+0x4>
  4026e8:	ucomiss %xmm12,%xmm8
  4026ec:	movaps %xmm8,%xmm14
  4026f0:	ja     4026fa <Ray_Trace+0x17a>
  4026f2:	xorps  0x16706(%rip),%xmm14        # 418e00 <__dso_handle+0x38>
  4026fa:	pxor   %xmm0,%xmm0
  4026fe:	cvtss2sd %xmm14,%xmm0
  402703:	ucomisd %xmm15,%xmm0
  402708:	jbe    402721 <Ray_Trace+0x1a1>
  40270a:	movss  0x166e9(%rip),%xmm10        # 418dfc <__dso_handle+0x34>
  402713:	divss  %xmm8,%xmm10
  402718:	movss  %xmm10,0x23fb07(%rip)        # 642228 <invinvjacobian+0x8>
  402721:	ucomiss %xmm12,%xmm7
  402725:	movaps %xmm7,%xmm1
  402728:	ja     402731 <Ray_Trace+0x1b1>
  40272a:	xorps  0x166cf(%rip),%xmm1        # 418e00 <__dso_handle+0x38>
  402731:	pxor   %xmm11,%xmm11
  402736:	cvtss2sd %xmm1,%xmm11
  40273b:	ucomisd %xmm15,%xmm11
  402740:	jbe    402759 <Ray_Trace+0x1d9>
  402742:	movss  0x166b1(%rip),%xmm13        # 418dfc <__dso_handle+0x34>
  40274b:	divss  %xmm7,%xmm13
  402750:	movss  %xmm13,0x23fad3(%rip)        # 64222c <invinvjacobian+0xc>
  402759:	ucomiss %xmm12,%xmm6
  40275d:	movaps %xmm6,%xmm9
  402761:	ja     40276b <Ray_Trace+0x1eb>
  402763:	xorps  0x16695(%rip),%xmm9        # 418e00 <__dso_handle+0x38>
  40276b:	pxor   %xmm14,%xmm14
  402770:	cvtss2sd %xmm9,%xmm14
  402775:	ucomisd %xmm15,%xmm14
  40277a:	jbe    402790 <Ray_Trace+0x210>
  40277c:	movss  0x16678(%rip),%xmm0        # 418dfc <__dso_handle+0x34>
  402784:	divss  %xmm6,%xmm0
  402788:	movss  %xmm0,0x23faa0(%rip)        # 642230 <invinvjacobian+0x10>
  402790:	ucomiss %xmm12,%xmm5
  402794:	movaps %xmm5,%xmm10
  402798:	ja     4027a2 <Ray_Trace+0x222>
  40279a:	xorps  0x1665e(%rip),%xmm10        # 418e00 <__dso_handle+0x38>
  4027a2:	pxor   %xmm8,%xmm8
  4027a7:	cvtss2sd %xmm10,%xmm8
  4027ac:	ucomisd %xmm15,%xmm8
  4027b1:	jbe    4027c7 <Ray_Trace+0x247>
  4027b3:	movss  0x16641(%rip),%xmm1        # 418dfc <__dso_handle+0x34>
  4027bb:	divss  %xmm5,%xmm1
  4027bf:	movss  %xmm1,0x23fa6d(%rip)        # 642234 <invinvjacobian+0x14>
  4027c7:	ucomiss %xmm12,%xmm4
  4027cb:	movaps %xmm4,%xmm11
  4027cf:	ja     4027d9 <Ray_Trace+0x259>
  4027d1:	xorps  0x16627(%rip),%xmm11        # 418e00 <__dso_handle+0x38>
  4027d9:	pxor   %xmm13,%xmm13
  4027de:	cvtss2sd %xmm11,%xmm13
  4027e3:	ucomisd %xmm15,%xmm13
  4027e8:	jbe    4027fe <Ray_Trace+0x27e>
  4027ea:	movss  0x1660a(%rip),%xmm7        # 418dfc <__dso_handle+0x34>
  4027f2:	divss  %xmm4,%xmm7
  4027f6:	movss  %xmm7,0x23fa3a(%rip)        # 642238 <invinvjacobian+0x18>
  4027fe:	ucomiss %xmm12,%xmm3
  402802:	movaps %xmm3,%xmm9
  402806:	ja     402810 <Ray_Trace+0x290>
  402808:	xorps  0x165f0(%rip),%xmm9        # 418e00 <__dso_handle+0x38>
  402810:	pxor   %xmm14,%xmm14
  402815:	cvtss2sd %xmm9,%xmm14
  40281a:	ucomisd %xmm15,%xmm14
  40281f:	jbe    402835 <Ray_Trace+0x2b5>
  402821:	movss  0x165d3(%rip),%xmm0        # 418dfc <__dso_handle+0x34>
  402829:	divss  %xmm3,%xmm0
  40282d:	movss  %xmm0,0x23fa07(%rip)        # 64223c <invinvjacobian+0x1c>
  402835:	ucomiss %xmm12,%xmm2
  402839:	movaps %xmm2,%xmm6
  40283c:	ja     402845 <Ray_Trace+0x2c5>
  40283e:	xorps  0x165bb(%rip),%xmm6        # 418e00 <__dso_handle+0x38>
  402845:	pxor   %xmm12,%xmm12
  40284a:	cvtss2sd %xmm6,%xmm12
  40284f:	ucomisd %xmm15,%xmm12
  402854:	jbe    40286d <Ray_Trace+0x2ed>
  402856:	movss  0x1659d(%rip),%xmm15        # 418dfc <__dso_handle+0x34>
  40285f:	divss  %xmm2,%xmm15
  402864:	movss  %xmm15,0x23f9d3(%rip)        # 642240 <invinvjacobian+0x20>
  40286d:	cmpw   $0x0,0x242947(%rip)        # 6451bc <adaptive>
  402875:	mov    0x23fa5c(%rip),%rax        # 6422d8 <Global>
  40287c:	movq   $0x0,0x23f9c9(%rip)        # 642250 <num_rays_traced>
  402887:	movq   $0x0,0x23f9b6(%rip)        # 642248 <num_traced_rays_hit_volume>
  402892:	movq   $0x0,0x23f963(%rip)        # 642200 <num_samples_trilirped>
  40289d:	lea    0x200878(%rax),%rdi
  4028a4:	je     402b70 <Ray_Trace+0x5f0>
  4028aa:	callq  401380 <pthread_mutex_lock@plt>
  4028af:	test   %eax,%eax
  4028b1:	jne    403124 <Ray_Trace+0xba4>
  4028b7:	mov    0x23fa1a(%rip),%r8        # 6422d8 <Global>
  4028be:	mov    0x2008d0(%r8),%r9
  4028c5:	mov    0x2008d8(%r8),%rbx
  4028cc:	lea    0x1(%r9),%r10
  4028d0:	cmp    0x241b79(%rip),%r10        # 644450 <num_nodes>
  4028d7:	mov    %r10,0x2008d0(%r8)
  4028de:	je     403005 <Ray_Trace+0xa85>
  4028e4:	lea    0x18(%rsp),%rsi
  4028e9:	mov    $0x1,%edi
  4028ee:	callq  401160 <pthread_setcancelstate@plt>
  4028f3:	jmp    40290f <Ray_Trace+0x38f>
  4028f5:	nopl   (%rax)
  4028f8:	lea    0x200878(%rdi),%rsi
  4028ff:	add    $0x2008a0,%rdi
  402906:	callq  401130 <pthread_cond_wait@plt>
  40290b:	test   %eax,%eax
  40290d:	jne    40291f <Ray_Trace+0x39f>
  40290f:	mov    0x23f9c2(%rip),%rdi        # 6422d8 <Global>
  402916:	cmp    %rbx,0x2008d8(%rdi)
  40291d:	je     4028f8 <Ray_Trace+0x378>
  40291f:	mov    0x18(%rsp),%edi
  402923:	lea    0x20(%rsp),%rsi
  402928:	mov    %rsi,(%rsp)
  40292c:	callq  401160 <pthread_setcancelstate@plt>
  402931:	mov    0x23f9a0(%rip),%rax        # 6422d8 <Global>
  402938:	lea    0x200878(%rax),%rdi
  40293f:	callq  401260 <pthread_mutex_unlock@plt>
  402944:	mov    (%rsp),%rdi
  402948:	xor    %esi,%esi
  40294a:	callq  4011a0 <gettimeofday@plt>
  40294f:	imul   $0xf4240,0x20(%rsp),%r12
  402958:	mov    %r14,%rdi
  40295b:	add    0x28(%rsp),%r12
  402960:	callq  40a990 <Pre_Shade>
  402965:	mov    0x23f96c(%rip),%rcx        # 6422d8 <Global>
  40296c:	lea    0x200908(%rcx),%rdi
  402973:	callq  401380 <pthread_mutex_lock@plt>
  402978:	mov    0x23f959(%rip),%rbp        # 6422d8 <Global>
  40297f:	mov    0x8(%rbp),%rdx
  402983:	lea    0x200908(%rbp),%rdi
  40298a:	sub    $0x1,%rdx
  40298e:	mov    %rdx,0x8(%rbp)
  402992:	callq  401260 <pthread_mutex_unlock@plt>
  402997:	mov    0x23f93a(%rip),%r13        # 6422d8 <Global>
  40299e:	xchg   %ax,%ax
  4029a0:	mov    0x8(%r13),%rdi
  4029a4:	test   %rdi,%rdi
  4029a7:	jne    4029a0 <Ray_Trace+0x420>
  4029a9:	mov    %r14,%rdi
  4029ac:	callq  401810 <Ray_Trace_Adaptively>
  4029b1:	mov    (%rsp),%rdi
  4029b5:	xor    %esi,%esi
  4029b7:	callq  4011a0 <gettimeofday@plt>
  4029bc:	mov    0x23f915(%rip),%r8        # 6422d8 <Global>
  4029c3:	imul   $0xf4240,0x20(%rsp),%rbp
  4029cc:	lea    0x200878(%r8),%rdi
  4029d3:	add    0x28(%rsp),%rbp
  4029d8:	callq  401380 <pthread_mutex_lock@plt>
  4029dd:	test   %eax,%eax
  4029df:	jne    403124 <Ray_Trace+0xba4>
  4029e5:	mov    0x23f8ec(%rip),%r9        # 6422d8 <Global>
  4029ec:	mov    0x2008d0(%r9),%r10
  4029f3:	mov    0x2008d8(%r9),%rbx
  4029fa:	lea    0x1(%r10),%r11
  4029fe:	cmp    0x241a4b(%rip),%r11        # 644450 <num_nodes>
  402a05:	mov    %r11,0x2008d0(%r9)
  402a0c:	je     4030c7 <Ray_Trace+0xb47>
  402a12:	lea    0x18(%rsp),%r13
  402a17:	mov    $0x1,%edi
  402a1c:	mov    %r13,%rsi
  402a1f:	callq  401160 <pthread_setcancelstate@plt>
  402a24:	jmp    402a47 <Ray_Trace+0x4c7>
  402a26:	nopw   %cs:0x0(%rax,%rax,1)
  402a30:	lea    0x200878(%rdi),%rsi
  402a37:	add    $0x2008a0,%rdi
  402a3e:	callq  401130 <pthread_cond_wait@plt>
  402a43:	test   %eax,%eax
  402a45:	jne    402a57 <Ray_Trace+0x4d7>
  402a47:	mov    0x23f88a(%rip),%rdi        # 6422d8 <Global>
  402a4e:	cmp    %rbx,0x2008d8(%rdi)
  402a55:	je     402a30 <Ray_Trace+0x4b0>
  402a57:	mov    (%rsp),%rsi
  402a5b:	mov    0x18(%rsp),%edi
  402a5f:	callq  401160 <pthread_setcancelstate@plt>
  402a64:	mov    0x23f86d(%rip),%rsi        # 6422d8 <Global>
  402a6b:	lea    0x200878(%rsi),%rdi
  402a72:	callq  401260 <pthread_mutex_unlock@plt>
  402a77:	mov    %r13,%rdx
  402a7a:	mov    %r12,%rsi
  402a7d:	mov    %rbp,%rdi
  402a80:	callq  403600 <mclock>
  402a85:	cmpq   $0x1,0x2426e3(%rip)        # 645170 <highest_sampling_boxlen>
  402a8d:	jg     402d7d <Ray_Trace+0x7fd>
  402a93:	mov    0x23f83e(%rip),%r12        # 6422d8 <Global>
  402a9a:	lea    0x200908(%r12),%rdi
  402aa2:	callq  401380 <pthread_mutex_lock@plt>
  402aa7:	mov    0x23f82a(%rip),%r13        # 6422d8 <Global>
  402aae:	lea    0x200908(%r13),%rdi
  402ab5:	callq  401260 <pthread_mutex_unlock@plt>
  402aba:	mov    0x23f817(%rip),%r11        # 6422d8 <Global>
  402ac1:	lea    0x200878(%r11),%rdi
  402ac8:	callq  401380 <pthread_mutex_lock@plt>
  402acd:	test   %eax,%eax
  402acf:	jne    403124 <Ray_Trace+0xba4>
  402ad5:	mov    0x23f7fc(%rip),%rsi        # 6422d8 <Global>
  402adc:	mov    0x2008d0(%rsi),%r8
  402ae3:	mov    0x2008d8(%rsi),%r14
  402aea:	lea    0x1(%r8),%rdi
  402aee:	cmp    0x24195b(%rip),%rdi        # 644450 <num_nodes>
  402af5:	mov    %rdi,0x2008d0(%rsi)
  402afc:	je     402d52 <Ray_Trace+0x7d2>
  402b02:	lea    0x10(%rsp),%rsi
  402b07:	mov    $0x1,%edi
  402b0c:	callq  401160 <pthread_setcancelstate@plt>
  402b11:	jmp    402b2f <Ray_Trace+0x5af>
  402b13:	nopl   0x0(%rax,%rax,1)
  402b18:	lea    0x200878(%rdi),%rsi
  402b1f:	add    $0x2008a0,%rdi
  402b26:	callq  401130 <pthread_cond_wait@plt>
  402b2b:	test   %eax,%eax
  402b2d:	jne    402b3f <Ray_Trace+0x5bf>
  402b2f:	mov    0x23f7a2(%rip),%rdi        # 6422d8 <Global>
  402b36:	cmp    %r14,0x2008d8(%rdi)
  402b3d:	je     402b18 <Ray_Trace+0x598>
  402b3f:	mov    0x10(%rsp),%edi
  402b43:	lea    0x14(%rsp),%rsi
  402b48:	callq  401160 <pthread_setcancelstate@plt>
  402b4d:	mov    0x23f784(%rip),%r9        # 6422d8 <Global>
  402b54:	lea    0x200878(%r9),%rdi
  402b5b:	callq  401260 <pthread_mutex_unlock@plt>
  402b60:	add    $0x38,%rsp
  402b64:	pop    %rbx
  402b65:	pop    %rbp
  402b66:	pop    %r12
  402b68:	pop    %r13
  402b6a:	pop    %r14
  402b6c:	pop    %r15
  402b6e:	retq   
  402b6f:	nop
  402b70:	callq  401380 <pthread_mutex_lock@plt>
  402b75:	test   %eax,%eax
  402b77:	jne    403124 <Ray_Trace+0xba4>
  402b7d:	mov    0x23f754(%rip),%rsi        # 6422d8 <Global>
  402b84:	mov    0x2008d0(%rsi),%rcx
  402b8b:	mov    0x2008d8(%rsi),%rbx
  402b92:	lea    0x1(%rcx),%rdx
  402b96:	cmp    0x2418b3(%rip),%rdx        # 644450 <num_nodes>
  402b9d:	mov    %rdx,0x2008d0(%rsi)
  402ba4:	je     40303b <Ray_Trace+0xabb>
  402baa:	lea    0x18(%rsp),%rsi
  402baf:	mov    $0x1,%edi
  402bb4:	callq  401160 <pthread_setcancelstate@plt>
  402bb9:	jmp    402bd7 <Ray_Trace+0x657>
  402bbb:	nopl   0x0(%rax,%rax,1)
  402bc0:	lea    0x200878(%rdi),%rsi
  402bc7:	add    $0x2008a0,%rdi
  402bce:	callq  401130 <pthread_cond_wait@plt>
  402bd3:	test   %eax,%eax
  402bd5:	jne    402be7 <Ray_Trace+0x667>
  402bd7:	mov    0x23f6fa(%rip),%rdi        # 6422d8 <Global>
  402bde:	cmp    %rbx,0x2008d8(%rdi)
  402be5:	je     402bc0 <Ray_Trace+0x640>
  402be7:	lea    0x20(%rsp),%rbp
  402bec:	mov    0x18(%rsp),%edi
  402bf0:	mov    %rbp,%rsi
  402bf3:	callq  401160 <pthread_setcancelstate@plt>
  402bf8:	mov    0x23f6d9(%rip),%r8        # 6422d8 <Global>
  402bff:	lea    0x200878(%r8),%rdi
  402c06:	callq  401260 <pthread_mutex_unlock@plt>
  402c0b:	xor    %esi,%esi
  402c0d:	mov    %rbp,%rdi
  402c10:	callq  4011a0 <gettimeofday@plt>
  402c15:	imul   $0xf4240,0x20(%rsp),%r13
  402c1e:	mov    %r14,%rdi
  402c21:	add    0x28(%rsp),%r13
  402c26:	callq  40a990 <Pre_Shade>
  402c2b:	mov    0x23f6a6(%rip),%r9        # 6422d8 <Global>
  402c32:	lea    0x200908(%r9),%rdi
  402c39:	callq  401380 <pthread_mutex_lock@plt>
  402c3e:	mov    0x23f693(%rip),%r10        # 6422d8 <Global>
  402c45:	mov    0x8(%r10),%r11
  402c49:	lea    0x200908(%r10),%rdi
  402c50:	sub    $0x1,%r11
  402c54:	mov    %r11,0x8(%r10)
  402c58:	callq  401260 <pthread_mutex_unlock@plt>
  402c5d:	mov    0x23f674(%rip),%r12        # 6422d8 <Global>
  402c64:	nopl   0x0(%rax)
  402c68:	mov    0x8(%r12),%r15
  402c6d:	test   %r15,%r15
  402c70:	jne    402c68 <Ray_Trace+0x6e8>
  402c72:	mov    %r14,%rdi
  402c75:	callq  401c80 <Ray_Trace_Non_Adaptively>
  402c7a:	xor    %esi,%esi
  402c7c:	mov    %rbp,%rdi
  402c7f:	callq  4011a0 <gettimeofday@plt>
  402c84:	mov    0x23f64d(%rip),%rax        # 6422d8 <Global>
  402c8b:	imul   $0xf4240,0x20(%rsp),%r12
  402c94:	lea    0x200878(%rax),%rdi
  402c9b:	add    0x28(%rsp),%r12
  402ca0:	callq  401380 <pthread_mutex_lock@plt>
  402ca5:	test   %eax,%eax
  402ca7:	jne    403124 <Ray_Trace+0xba4>
  402cad:	mov    0x23f624(%rip),%rsi        # 6422d8 <Global>
  402cb4:	mov    0x2008d0(%rsi),%rcx
  402cbb:	mov    0x2008d8(%rsi),%rbx
  402cc2:	lea    0x1(%rcx),%rdx
  402cc6:	cmp    0x241783(%rip),%rdx        # 644450 <num_nodes>
  402ccd:	mov    %rdx,0x2008d0(%rsi)
  402cd4:	je     403096 <Ray_Trace+0xb16>
  402cda:	lea    0x18(%rsp),%r14
  402cdf:	mov    $0x1,%edi
  402ce4:	mov    %r14,%rsi
  402ce7:	callq  401160 <pthread_setcancelstate@plt>
  402cec:	jmp    402d07 <Ray_Trace+0x787>
  402cee:	xchg   %ax,%ax
  402cf0:	lea    0x200878(%rdi),%rsi
  402cf7:	add    $0x2008a0,%rdi
  402cfe:	callq  401130 <pthread_cond_wait@plt>
  402d03:	test   %eax,%eax
  402d05:	jne    402d17 <Ray_Trace+0x797>
  402d07:	mov    0x23f5ca(%rip),%rdi        # 6422d8 <Global>
  402d0e:	cmp    %rbx,0x2008d8(%rdi)
  402d15:	je     402cf0 <Ray_Trace+0x770>
  402d17:	mov    0x18(%rsp),%edi
  402d1b:	mov    %rbp,%rsi
  402d1e:	callq  401160 <pthread_setcancelstate@plt>
  402d23:	mov    0x23f5ae(%rip),%rdi        # 6422d8 <Global>
  402d2a:	lea    0x200878(%rdi),%rdi
  402d31:	callq  401260 <pthread_mutex_unlock@plt>
  402d36:	mov    %r14,%rdx
  402d39:	mov    %r13,%rsi
  402d3c:	mov    %r12,%rdi
  402d3f:	callq  403600 <mclock>
  402d44:	movq   $0x0,0x20(%rsp)
  402d4d:	jmpq   402a93 <Ray_Trace+0x513>
  402d52:	xor    %ecx,%ecx
  402d54:	test   %r14,%r14
  402d57:	lea    0x2008a0(%rsi),%rdi
  402d5e:	sete   %cl
  402d61:	movq   $0x0,0x2008d0(%rsi)
  402d6c:	mov    %rcx,0x2008d8(%rsi)
  402d73:	callq  401100 <pthread_cond_broadcast@plt>
  402d78:	jmpq   402b4d <Ray_Trace+0x5cd>
  402d7d:	mov    0x23f554(%rip),%rax        # 6422d8 <Global>
  402d84:	lea    0x200878(%rax),%rdi
  402d8b:	callq  401380 <pthread_mutex_lock@plt>
  402d90:	test   %eax,%eax
  402d92:	jne    403124 <Ray_Trace+0xba4>
  402d98:	mov    0x23f539(%rip),%rdi        # 6422d8 <Global>
  402d9f:	mov    0x2008d0(%rdi),%rcx
  402da6:	mov    0x2008d8(%rdi),%r15
  402dad:	lea    0x1(%rcx),%rdx
  402db1:	cmp    0x241698(%rip),%rdx        # 644450 <num_nodes>
  402db8:	mov    %rdx,0x2008d0(%rdi)
  402dbf:	je     40306c <Ray_Trace+0xaec>
  402dc5:	lea    0x14(%rsp),%rsi
  402dca:	mov    $0x1,%edi
  402dcf:	callq  401160 <pthread_setcancelstate@plt>
  402dd4:	jmp    402df7 <Ray_Trace+0x877>
  402dd6:	nopw   %cs:0x0(%rax,%rax,1)
  402de0:	lea    0x200878(%rdi),%rsi
  402de7:	add    $0x2008a0,%rdi
  402dee:	callq  401130 <pthread_cond_wait@plt>
  402df3:	test   %eax,%eax
  402df5:	jne    402e07 <Ray_Trace+0x887>
  402df7:	mov    0x23f4da(%rip),%rdi        # 6422d8 <Global>
  402dfe:	cmp    %r15,0x2008d8(%rdi)
  402e05:	je     402de0 <Ray_Trace+0x860>
  402e07:	mov    (%rsp),%rsi
  402e0b:	mov    0x14(%rsp),%edi
  402e0f:	callq  401160 <pthread_setcancelstate@plt>
  402e14:	mov    0x23f4bd(%rip),%r9        # 6422d8 <Global>
  402e1b:	lea    0x200878(%r9),%rdi
  402e22:	callq  401260 <pthread_mutex_unlock@plt>
  402e27:	mov    (%rsp),%rdi
  402e2b:	xor    %esi,%esi
  402e2d:	callq  4011a0 <gettimeofday@plt>
  402e32:	imul   $0xf4240,0x20(%rsp),%r10
  402e3b:	mov    0x241606(%rip),%rcx        # 644448 <num_blocks>
  402e42:	add    0x28(%rsp),%r10
  402e47:	test   %rcx,%rcx
  402e4a:	mov    %r10,0x8(%rsp)
  402e4f:	jle    402f32 <Ray_Trace+0x9b2>
  402e55:	mov    0x242344(%rip),%r8        # 6451a0 <block_ylen>
  402e5c:	mov    0x24237d(%rip),%r11        # 6451e0 <block_xlen>
  402e63:	xor    %r13d,%r13d
  402e66:	nopw   %cs:0x0(%rax,%rax,1)
  402e70:	lea    0x0(%r13,%r14,1),%rax
  402e75:	cqto   
  402e77:	idivq  0x23f432(%rip)        # 6422b0 <num_xblocks>
  402e7e:	imul   %r8,%rax
  402e82:	imul   %r11,%rdx
  402e86:	lea    (%rax,%r8,1),%rdi
  402e8a:	mov    %rax,%r12
  402e8d:	mov    %rdx,%rbp
  402e90:	cmp    %rax,%rdi
  402e93:	jle    402f22 <Ray_Trace+0x9a2>
  402e99:	cmp    %rax,0x241588(%rip)        # 644428 <image_len+0x8>
  402ea0:	jle    402f22 <Ray_Trace+0x9a2>
  402ea6:	mov    0x2422c3(%rip),%rdx        # 645170 <highest_sampling_boxlen>
  402ead:	lea    0x0(%rbp,%r11,1),%rsi
  402eb2:	mov    %rax,%rbx
  402eb5:	nopl   (%rax)
  402eb8:	cmp    %rsi,%rbp
  402ebb:	jge    402f0a <Ray_Trace+0x98a>
  402ebd:	cmp    0x24155c(%rip),%rbp        # 644420 <image_len>
  402ec4:	mov    %rbp,%r15
  402ec7:	jl     402ed9 <Ray_Trace+0x959>
  402ec9:	jmp    402f0a <Ray_Trace+0x98a>
  402ecb:	nopl   0x0(%rax,%rax,1)
  402ed0:	cmp    0x241549(%rip),%r15        # 644420 <image_len>
  402ed7:	jge    402eff <Ray_Trace+0x97f>
  402ed9:	mov    %rbx,%rsi
  402edc:	mov    %r15,%rdi
  402edf:	callq  402230 <Interpolate_Recursive_Box>
  402ee4:	mov    0x2422f5(%rip),%r11        # 6451e0 <block_xlen>
  402eeb:	mov    0x24227e(%rip),%rdx        # 645170 <highest_sampling_boxlen>
  402ef2:	lea    0x0(%rbp,%r11,1),%rsi
  402ef7:	add    %rdx,%r15
  402efa:	cmp    %rsi,%r15
  402efd:	jl     402ed0 <Ray_Trace+0x950>
  402eff:	mov    0x24229a(%rip),%r8        # 6451a0 <block_ylen>
  402f06:	lea    (%r12,%r8,1),%rdi
  402f0a:	add    %rdx,%rbx
  402f0d:	cmp    %rdi,%rbx
  402f10:	jge    402f1b <Ray_Trace+0x99b>
  402f12:	cmp    0x24150f(%rip),%rbx        # 644428 <image_len+0x8>
  402f19:	jl     402eb8 <Ray_Trace+0x938>
  402f1b:	mov    0x241526(%rip),%rcx        # 644448 <num_blocks>
  402f22:	add    0x241527(%rip),%r13        # 644450 <num_nodes>
  402f29:	cmp    %rcx,%r13
  402f2c:	jl     402e70 <Ray_Trace+0x8f0>
  402f32:	mov    (%rsp),%rdi
  402f36:	xor    %esi,%esi
  402f38:	callq  4011a0 <gettimeofday@plt>
  402f3d:	mov    0x23f394(%rip),%r14        # 6422d8 <Global>
  402f44:	imul   $0xf4240,0x20(%rsp),%rbx
  402f4d:	lea    0x200878(%r14),%rdi
  402f54:	add    0x28(%rsp),%rbx
  402f59:	callq  401380 <pthread_mutex_lock@plt>
  402f5e:	test   %eax,%eax
  402f60:	jne    403124 <Ray_Trace+0xba4>
  402f66:	mov    0x23f36b(%rip),%r9        # 6422d8 <Global>
  402f6d:	mov    0x2008d0(%r9),%r10
  402f74:	mov    0x2008d8(%r9),%r15
  402f7b:	lea    0x1(%r10),%rax
  402f7f:	cmp    0x2414ca(%rip),%rax        # 644450 <num_nodes>
  402f86:	mov    %rax,0x2008d0(%r9)
  402f8d:	je     4030f9 <Ray_Trace+0xb79>
  402f93:	lea    0x14(%rsp),%rsi
  402f98:	mov    $0x1,%edi
  402f9d:	callq  401160 <pthread_setcancelstate@plt>
  402fa2:	jmp    402fbf <Ray_Trace+0xa3f>
  402fa4:	nopl   0x0(%rax)
  402fa8:	lea    0x200878(%rdi),%rsi
  402faf:	add    $0x2008a0,%rdi
  402fb6:	callq  401130 <pthread_cond_wait@plt>
  402fbb:	test   %eax,%eax
  402fbd:	jne    402fcf <Ray_Trace+0xa4f>
  402fbf:	mov    0x23f312(%rip),%rdi        # 6422d8 <Global>
  402fc6:	cmp    %r15,0x2008d8(%rdi)
  402fcd:	je     402fa8 <Ray_Trace+0xa28>
  402fcf:	mov    (%rsp),%rsi
  402fd3:	mov    0x14(%rsp),%edi
  402fd7:	callq  401160 <pthread_setcancelstate@plt>
  402fdc:	mov    0x23f2f5(%rip),%rbp        # 6422d8 <Global>
  402fe3:	lea    0x200878(%rbp),%rdi
  402fea:	callq  401260 <pthread_mutex_unlock@plt>
  402fef:	mov    (%rsp),%rdx
  402ff3:	mov    0x8(%rsp),%rsi
  402ff8:	mov    %rbx,%rdi
  402ffb:	callq  403600 <mclock>
  403000:	jmpq   402a93 <Ray_Trace+0x513>
  403005:	xor    %r11d,%r11d
  403008:	test   %rbx,%rbx
  40300b:	lea    0x2008a0(%r8),%rdi
  403012:	sete   %r11b
  403016:	lea    0x20(%rsp),%r15
  40301b:	movq   $0x0,0x2008d0(%r8)
  403026:	mov    %r11,0x2008d8(%r8)
  40302d:	callq  401100 <pthread_cond_broadcast@plt>
  403032:	mov    %r15,(%rsp)
  403036:	jmpq   402931 <Ray_Trace+0x3b1>
  40303b:	xor    %edi,%edi
  40303d:	test   %rbx,%rbx
  403040:	movq   $0x0,0x2008d0(%rsi)
  40304b:	sete   %dil
  40304f:	lea    0x20(%rsp),%rbp
  403054:	mov    %rdi,0x2008d8(%rsi)
  40305b:	lea    0x2008a0(%rsi),%rdi
  403062:	callq  401100 <pthread_cond_broadcast@plt>
  403067:	jmpq   402bf8 <Ray_Trace+0x678>
  40306c:	xor    %r8d,%r8d
  40306f:	test   %r15,%r15
  403072:	movq   $0x0,0x2008d0(%rdi)
  40307d:	sete   %r8b
  403081:	lea    0x2008a0(%rdi),%rdi
  403088:	mov    %r8,0x38(%rdi)
  40308c:	callq  401100 <pthread_cond_broadcast@plt>
  403091:	jmpq   402e14 <Ray_Trace+0x894>
  403096:	xor    %ebp,%ebp
  403098:	test   %rbx,%rbx
  40309b:	lea    0x2008a0(%rsi),%rdi
  4030a2:	sete   %bpl
  4030a6:	movq   $0x0,0x2008d0(%rsi)
  4030b1:	lea    0x18(%rsp),%r14
  4030b6:	mov    %rbp,0x2008d8(%rsi)
  4030bd:	callq  401100 <pthread_cond_broadcast@plt>
  4030c2:	jmpq   402d23 <Ray_Trace+0x7a3>
  4030c7:	xor    %r15d,%r15d
  4030ca:	test   %rbx,%rbx
  4030cd:	lea    0x2008a0(%r9),%rdi
  4030d4:	sete   %r15b
  4030d8:	movq   $0x0,0x2008d0(%r9)
  4030e3:	lea    0x18(%rsp),%r13
  4030e8:	mov    %r15,0x2008d8(%r9)
  4030ef:	callq  401100 <pthread_cond_broadcast@plt>
  4030f4:	jmpq   402a64 <Ray_Trace+0x4e4>
  4030f9:	xor    %edx,%edx
  4030fb:	test   %r15,%r15
  4030fe:	lea    0x2008a0(%r9),%rdi
  403105:	sete   %dl
  403108:	movq   $0x0,0x2008d0(%r9)
  403113:	mov    %rdx,0x2008d8(%r9)
  40311a:	callq  401100 <pthread_cond_broadcast@plt>
  40311f:	jmpq   402fdc <Ray_Trace+0xa5c>
  403124:	mov    $0x418dd0,%edi
  403129:	callq  401110 <puts@plt>
  40312e:	or     $0xffffffff,%edi
  403131:	callq  401340 <exit@plt>
  403136:	nopw   %cs:0x0(%rax,%rax,1)

0000000000403140 <Create_File>:
  403140:	push   %rbp
  403141:	push   %rbx
  403142:	mov    $0x1a4,%esi
  403147:	mov    %rdi,%rbp
  40314a:	sub    $0x8,%rsp
  40314e:	callq  401320 <creat@plt>
  403153:	cmp    $0xffffffff,%eax
  403156:	mov    %eax,%ebx
  403158:	je     403168 <Create_File+0x28>
  40315a:	add    $0x8,%rsp
  40315e:	mov    %ebx,%eax
  403160:	pop    %rbx
  403161:	pop    %rbp
  403162:	retq   
  403163:	nopl   0x0(%rax,%rax,1)
  403168:	mov    %rbp,%rsi
  40316b:	xor    %eax,%eax
  40316d:	mov    $0x418e18,%edi
  403172:	callq  403650 <Error>
  403177:	add    $0x8,%rsp
  40317b:	mov    %ebx,%eax
  40317d:	pop    %rbx
  40317e:	pop    %rbp
  40317f:	retq   

0000000000403180 <Open_File>:
  403180:	push   %rbp
  403181:	push   %rbx
  403182:	xor    %esi,%esi
  403184:	xor    %eax,%eax
  403186:	mov    %rdi,%rbp
  403189:	sub    $0x8,%rsp
  40318d:	callq  4012e0 <open@plt>
  403192:	cmp    $0xffffffff,%eax
  403195:	mov    %eax,%ebx
  403197:	je     4031a8 <Open_File+0x28>
  403199:	add    $0x8,%rsp
  40319d:	mov    %ebx,%eax
  40319f:	pop    %rbx
  4031a0:	pop    %rbp
  4031a1:	retq   
  4031a2:	nopw   0x0(%rax,%rax,1)
  4031a8:	mov    %rbp,%rsi
  4031ab:	xor    %eax,%eax
  4031ad:	mov    $0x418e2d,%edi
  4031b2:	callq  403650 <Error>
  4031b7:	add    $0x8,%rsp
  4031bb:	mov    %ebx,%eax
  4031bd:	pop    %rbx
  4031be:	pop    %rbp
  4031bf:	retq   

00000000004031c0 <Write_Bytes>:
  4031c0:	push   %r14
  4031c2:	cmp    $0x7ffe,%rdx
  4031c9:	push   %r13
  4031cb:	mov    %rdx,%r14
  4031ce:	push   %r12
  4031d0:	mov    $0x7ffe,%edx
  4031d5:	push   %rbp
  4031d6:	push   %rbx
  4031d7:	cmovle %r14,%rdx
  4031db:	mov    %edi,%ebp
  4031dd:	mov    %rsi,%r12
  4031e0:	callq  401120 <write@plt>
  4031e5:	cmp    $0xffffffffffffffff,%rax
  4031e9:	mov    %rax,%rbx
  4031ec:	je     403250 <Write_Bytes+0x90>
  4031ee:	cmp    %rax,%r14
  4031f1:	jle    403250 <Write_Bytes+0x90>
  4031f3:	mov    $0x7ffe,%r13d
  4031f9:	jmp    403208 <Write_Bytes+0x48>
  4031fb:	nopl   0x0(%rax,%rax,1)
  403200:	add    %rax,%rbx
  403203:	cmp    %rbx,%r14
  403206:	jle    403250 <Write_Bytes+0x90>
  403208:	mov    %r14,%rdx
  40320b:	lea    (%r12,%rbx,1),%rsi
  40320f:	mov    %ebp,%edi
  403211:	sub    %rbx,%rdx
  403214:	cmp    $0x7ffe,%rdx
  40321b:	cmovg  %r13,%rdx
  40321f:	callq  401120 <write@plt>
  403224:	cmp    $0xffffffffffffffff,%rax
  403228:	jne    403200 <Write_Bytes+0x40>
  40322a:	mov    %ebp,%edi
  40322c:	callq  4011f0 <close@plt>
  403231:	cmp    $0xffffffff,%eax
  403234:	je     403260 <Write_Bytes+0xa0>
  403236:	pop    %rbx
  403237:	mov    %ebp,%esi
  403239:	mov    $0x418e59,%edi
  40323e:	xor    %eax,%eax
  403240:	pop    %rbp
  403241:	pop    %r12
  403243:	pop    %r13
  403245:	pop    %r14
  403247:	jmpq   403650 <Error>
  40324c:	nopl   0x0(%rax)
  403250:	cmp    %r14,%rbx
  403253:	jne    40322a <Write_Bytes+0x6a>
  403255:	pop    %rbx
  403256:	pop    %rbp
  403257:	pop    %r12
  403259:	pop    %r13
  40325b:	pop    %r14
  40325d:	retq   
  40325e:	xchg   %ax,%ax
  403260:	mov    %ebp,%esi
  403262:	mov    $0x418e40,%edi
  403267:	xor    %eax,%eax
  403269:	callq  403650 <Error>
  40326e:	jmp    403236 <Write_Bytes+0x76>

0000000000403270 <Write_Shorts>:
  403270:	push   %r14
  403272:	cmp    $0x7ffe,%rdx
  403279:	push   %r13
  40327b:	mov    %rdx,%r14
  40327e:	push   %r12
  403280:	mov    $0x7ffe,%edx
  403285:	push   %rbp
  403286:	push   %rbx
  403287:	cmovle %r14,%rdx
  40328b:	mov    %edi,%ebp
  40328d:	mov    %rsi,%r12
  403290:	callq  401120 <write@plt>
  403295:	cmp    $0xffffffffffffffff,%rax
  403299:	mov    %rax,%rbx
  40329c:	je     403300 <Write_Shorts+0x90>
  40329e:	cmp    %rax,%r14
  4032a1:	jle    403300 <Write_Shorts+0x90>
  4032a3:	mov    $0x7ffe,%r13d
  4032a9:	jmp    4032b8 <Write_Shorts+0x48>
  4032ab:	nopl   0x0(%rax,%rax,1)
  4032b0:	add    %rax,%rbx
  4032b3:	cmp    %rbx,%r14
  4032b6:	jle    403300 <Write_Shorts+0x90>
  4032b8:	mov    %r14,%rdx
  4032bb:	lea    (%r12,%rbx,1),%rsi
  4032bf:	mov    %ebp,%edi
  4032c1:	sub    %rbx,%rdx
  4032c4:	cmp    $0x7ffe,%rdx
  4032cb:	cmovg  %r13,%rdx
  4032cf:	callq  401120 <write@plt>
  4032d4:	cmp    $0xffffffffffffffff,%rax
  4032d8:	jne    4032b0 <Write_Shorts+0x40>
  4032da:	mov    %ebp,%edi
  4032dc:	callq  4011f0 <close@plt>
  4032e1:	cmp    $0xffffffff,%eax
  4032e4:	je     403310 <Write_Shorts+0xa0>
  4032e6:	pop    %rbx
  4032e7:	mov    %ebp,%esi
  4032e9:	mov    $0x418e59,%edi
  4032ee:	xor    %eax,%eax
  4032f0:	pop    %rbp
  4032f1:	pop    %r12
  4032f3:	pop    %r13
  4032f5:	pop    %r14
  4032f7:	jmpq   403650 <Error>
  4032fc:	nopl   0x0(%rax)
  403300:	cmp    %rbx,%r14
  403303:	jne    4032da <Write_Shorts+0x6a>
  403305:	pop    %rbx
  403306:	pop    %rbp
  403307:	pop    %r12
  403309:	pop    %r13
  40330b:	pop    %r14
  40330d:	retq   
  40330e:	xchg   %ax,%ax
  403310:	mov    %ebp,%esi
  403312:	mov    $0x418e40,%edi
  403317:	xor    %eax,%eax
  403319:	callq  403650 <Error>
  40331e:	jmp    4032e6 <Write_Shorts+0x76>

0000000000403320 <Write_Longs>:
  403320:	push   %r14
  403322:	cmp    $0x7ffe,%rdx
  403329:	push   %r13
  40332b:	mov    %rdx,%r14
  40332e:	push   %r12
  403330:	mov    $0x7ffe,%edx
  403335:	push   %rbp
  403336:	push   %rbx
  403337:	cmovle %r14,%rdx
  40333b:	mov    %edi,%ebp
  40333d:	mov    %rsi,%r12
  403340:	callq  401120 <write@plt>
  403345:	cmp    $0xffffffffffffffff,%rax
  403349:	mov    %rax,%rbx
  40334c:	je     4033b0 <Write_Longs+0x90>
  40334e:	cmp    %rax,%r14
  403351:	jle    4033b0 <Write_Longs+0x90>
  403353:	mov    $0x7ffe,%r13d
  403359:	jmp    403368 <Write_Longs+0x48>
  40335b:	nopl   0x0(%rax,%rax,1)
  403360:	add    %rax,%rbx
  403363:	cmp    %rbx,%r14
  403366:	jle    4033b0 <Write_Longs+0x90>
  403368:	mov    %r14,%rdx
  40336b:	lea    (%r12,%rbx,1),%rsi
  40336f:	mov    %ebp,%edi
  403371:	sub    %rbx,%rdx
  403374:	cmp    $0x7ffe,%rdx
  40337b:	cmovg  %r13,%rdx
  40337f:	callq  401120 <write@plt>
  403384:	cmp    $0xffffffffffffffff,%rax
  403388:	jne    403360 <Write_Longs+0x40>
  40338a:	mov    %ebp,%edi
  40338c:	callq  4011f0 <close@plt>
  403391:	cmp    $0xffffffff,%eax
  403394:	je     4033c0 <Write_Longs+0xa0>
  403396:	pop    %rbx
  403397:	mov    %ebp,%esi
  403399:	mov    $0x418e59,%edi
  40339e:	xor    %eax,%eax
  4033a0:	pop    %rbp
  4033a1:	pop    %r12
  4033a3:	pop    %r13
  4033a5:	pop    %r14
  4033a7:	jmpq   403650 <Error>
  4033ac:	nopl   0x0(%rax)
  4033b0:	cmp    %rbx,%r14
  4033b3:	jne    40338a <Write_Longs+0x6a>
  4033b5:	pop    %rbx
  4033b6:	pop    %rbp
  4033b7:	pop    %r12
  4033b9:	pop    %r13
  4033bb:	pop    %r14
  4033bd:	retq   
  4033be:	xchg   %ax,%ax
  4033c0:	mov    %ebp,%esi
  4033c2:	mov    $0x418e40,%edi
  4033c7:	xor    %eax,%eax
  4033c9:	callq  403650 <Error>
  4033ce:	jmp    403396 <Write_Longs+0x76>

00000000004033d0 <Read_Bytes>:
  4033d0:	push   %r14
  4033d2:	cmp    $0x7ffe,%rdx
  4033d9:	push   %r13
  4033db:	mov    %rdx,%r14
  4033de:	push   %r12
  4033e0:	mov    $0x7ffe,%edx
  4033e5:	push   %rbp
  4033e6:	push   %rbx
  4033e7:	cmovle %r14,%rdx
  4033eb:	mov    %edi,%ebp
  4033ed:	mov    %rsi,%r12
  4033f0:	callq  401200 <read@plt>
  4033f5:	mov    %rax,%rbx
  4033f8:	add    $0x1,%rax
  4033fc:	cmp    $0x1,%rax
  403400:	jbe    403460 <Read_Bytes+0x90>
  403402:	cmp    %rbx,%r14
  403405:	jle    403460 <Read_Bytes+0x90>
  403407:	mov    $0x7ffe,%r13d
  40340d:	jmp    403418 <Read_Bytes+0x48>
  40340f:	nop
  403410:	add    %rax,%rbx
  403413:	cmp    %rbx,%r14
  403416:	jle    403460 <Read_Bytes+0x90>
  403418:	mov    %r14,%rdx
  40341b:	lea    (%r12,%rbx,1),%rsi
  40341f:	mov    %ebp,%edi
  403421:	sub    %rbx,%rdx
  403424:	cmp    $0x7ffe,%rdx
  40342b:	cmovg  %r13,%rdx
  40342f:	callq  401200 <read@plt>
  403434:	lea    0x1(%rax),%rdx
  403438:	cmp    $0x1,%rdx
  40343c:	ja     403410 <Read_Bytes+0x40>
  40343e:	mov    %ebp,%edi
  403440:	callq  4011f0 <close@plt>
  403445:	cmp    $0xffffffff,%eax
  403448:	je     403470 <Read_Bytes+0xa0>
  40344a:	pop    %rbx
  40344b:	mov    %ebp,%esi
  40344d:	mov    $0x418e76,%edi
  403452:	xor    %eax,%eax
  403454:	pop    %rbp
  403455:	pop    %r12
  403457:	pop    %r13
  403459:	pop    %r14
  40345b:	jmpq   403650 <Error>
  403460:	cmp    %r14,%rbx
  403463:	jne    40343e <Read_Bytes+0x6e>
  403465:	pop    %rbx
  403466:	pop    %rbp
  403467:	pop    %r12
  403469:	pop    %r13
  40346b:	pop    %r14
  40346d:	retq   
  40346e:	xchg   %ax,%ax
  403470:	mov    %ebp,%esi
  403472:	mov    $0x418e40,%edi
  403477:	xor    %eax,%eax
  403479:	callq  403650 <Error>
  40347e:	jmp    40344a <Read_Bytes+0x7a>

0000000000403480 <Read_Shorts>:
  403480:	push   %r14
  403482:	cmp    $0x7ffe,%rdx
  403489:	push   %r13
  40348b:	mov    %rdx,%r14
  40348e:	push   %r12
  403490:	mov    $0x7ffe,%edx
  403495:	push   %rbp
  403496:	push   %rbx
  403497:	cmovle %r14,%rdx
  40349b:	mov    %edi,%ebp
  40349d:	mov    %rsi,%r12
  4034a0:	callq  401200 <read@plt>
  4034a5:	mov    %rax,%rbx
  4034a8:	add    $0x1,%rax
  4034ac:	cmp    $0x1,%rax
  4034b0:	jbe    403510 <Read_Shorts+0x90>
  4034b2:	cmp    %rbx,%r14
  4034b5:	jle    403510 <Read_Shorts+0x90>
  4034b7:	mov    $0x7ffe,%r13d
  4034bd:	jmp    4034c8 <Read_Shorts+0x48>
  4034bf:	nop
  4034c0:	add    %rax,%rbx
  4034c3:	cmp    %rbx,%r14
  4034c6:	jle    403510 <Read_Shorts+0x90>
  4034c8:	mov    %r14,%rdx
  4034cb:	lea    (%r12,%rbx,1),%rsi
  4034cf:	mov    %ebp,%edi
  4034d1:	sub    %rbx,%rdx
  4034d4:	cmp    $0x7ffe,%rdx
  4034db:	cmovg  %r13,%rdx
  4034df:	callq  401200 <read@plt>
  4034e4:	lea    0x1(%rax),%rdx
  4034e8:	cmp    $0x1,%rdx
  4034ec:	ja     4034c0 <Read_Shorts+0x40>
  4034ee:	mov    %ebp,%edi
  4034f0:	callq  4011f0 <close@plt>
  4034f5:	cmp    $0xffffffff,%eax
  4034f8:	je     403520 <Read_Shorts+0xa0>
  4034fa:	pop    %rbx
  4034fb:	mov    %ebp,%esi
  4034fd:	mov    $0x418e76,%edi
  403502:	xor    %eax,%eax
  403504:	pop    %rbp
  403505:	pop    %r12
  403507:	pop    %r13
  403509:	pop    %r14
  40350b:	jmpq   403650 <Error>
  403510:	cmp    %rbx,%r14
  403513:	jne    4034ee <Read_Shorts+0x6e>
  403515:	pop    %rbx
  403516:	pop    %rbp
  403517:	pop    %r12
  403519:	pop    %r13
  40351b:	pop    %r14
  40351d:	retq   
  40351e:	xchg   %ax,%ax
  403520:	mov    %ebp,%esi
  403522:	mov    $0x418e40,%edi
  403527:	xor    %eax,%eax
  403529:	callq  403650 <Error>
  40352e:	jmp    4034fa <Read_Shorts+0x7a>

0000000000403530 <Read_Longs>:
  403530:	push   %r14
  403532:	cmp    $0x7ffe,%rdx
  403539:	push   %r13
  40353b:	mov    %rdx,%r14
  40353e:	push   %r12
  403540:	mov    $0x7ffe,%edx
  403545:	push   %rbp
  403546:	push   %rbx
  403547:	cmovle %r14,%rdx
  40354b:	mov    %edi,%ebp
  40354d:	mov    %rsi,%r12
  403550:	callq  401200 <read@plt>
  403555:	mov    %rax,%rbx
  403558:	add    $0x1,%rax
  40355c:	cmp    $0x1,%rax
  403560:	jbe    4035c0 <Read_Longs+0x90>
  403562:	cmp    %rbx,%r14
  403565:	jle    4035c0 <Read_Longs+0x90>
  403567:	mov    $0x7ffe,%r13d
  40356d:	jmp    403578 <Read_Longs+0x48>
  40356f:	nop
  403570:	add    %rax,%rbx
  403573:	cmp    %rbx,%r14
  403576:	jle    4035c0 <Read_Longs+0x90>
  403578:	mov    %r14,%rdx
  40357b:	lea    (%r12,%rbx,1),%rsi
  40357f:	mov    %ebp,%edi
  403581:	sub    %rbx,%rdx
  403584:	cmp    $0x7ffe,%rdx
  40358b:	cmovg  %r13,%rdx
  40358f:	callq  401200 <read@plt>
  403594:	lea    0x1(%rax),%rdx
  403598:	cmp    $0x1,%rdx
  40359c:	ja     403570 <Read_Longs+0x40>
  40359e:	mov    %ebp,%edi
  4035a0:	callq  4011f0 <close@plt>
  4035a5:	cmp    $0xffffffff,%eax
  4035a8:	je     4035d0 <Read_Longs+0xa0>
  4035aa:	pop    %rbx
  4035ab:	mov    %ebp,%esi
  4035ad:	mov    $0x418e76,%edi
  4035b2:	xor    %eax,%eax
  4035b4:	pop    %rbp
  4035b5:	pop    %r12
  4035b7:	pop    %r13
  4035b9:	pop    %r14
  4035bb:	jmpq   403650 <Error>
  4035c0:	cmp    %rbx,%r14
  4035c3:	jne    40359e <Read_Longs+0x6e>
  4035c5:	pop    %rbx
  4035c6:	pop    %rbp
  4035c7:	pop    %r12
  4035c9:	pop    %r13
  4035cb:	pop    %r14
  4035cd:	retq   
  4035ce:	xchg   %ax,%ax
  4035d0:	mov    %ebp,%esi
  4035d2:	mov    $0x418e40,%edi
  4035d7:	xor    %eax,%eax
  4035d9:	callq  403650 <Error>
  4035de:	jmp    4035aa <Read_Longs+0x7a>

00000000004035e0 <Close_File>:
  4035e0:	push   %rbx
  4035e1:	mov    %edi,%ebx
  4035e3:	callq  4011f0 <close@plt>
  4035e8:	cmp    $0xffffffff,%eax
  4035eb:	je     4035f0 <Close_File+0x10>
  4035ed:	pop    %rbx
  4035ee:	retq   
  4035ef:	nop
  4035f0:	mov    %ebx,%esi
  4035f2:	mov    $0x418e40,%edi
  4035f7:	xor    %eax,%eax
  4035f9:	pop    %rbx
  4035fa:	jmpq   403650 <Error>
  4035ff:	nop

0000000000403600 <mclock>:
  403600:	cmp    %rsi,%rdi
  403603:	mov    %rdx,%rcx
  403606:	jl     403630 <mclock+0x30>
  403608:	sub    %rsi,%rdi
  40360b:	movabs $0x20c49ba5e353f7cf,%rdx
  403615:	shr    $0x3,%rdi
  403619:	mov    %rdi,%rax
  40361c:	mul    %rdx
  40361f:	shr    $0x4,%rdx
  403623:	mov    %rdx,(%rcx)
  403626:	retq   
  403627:	nopw   0x0(%rax,%rax,1)
  403630:	sub    %rsi,%rdi
  403633:	lea    -0x1(%rdi),%rax
  403637:	movabs $0x20c49ba5e353f7cf,%rdi
  403641:	shr    $0x3,%rax
  403645:	mul    %rdi
  403648:	shr    $0x4,%rdx
  40364c:	mov    %rdx,(%rcx)
  40364f:	retq   

0000000000403650 <Error>:
  403650:	sub    $0x58,%rsp
  403654:	lea    0x60(%rsp),%rax
  403659:	mov    %rdx,0x30(%rsp)
  40365e:	lea    0x20(%rsp),%rdx
  403663:	mov    %rsi,0x28(%rsp)
  403668:	mov    %rcx,0x38(%rsp)
  40366d:	xor    %ecx,%ecx
  40366f:	mov    %rax,0x10(%rsp)
  403674:	addq   $0x8,0x10(%rsp)
  40367a:	xor    %eax,%eax
  40367c:	mov    %r8,0x40(%rsp)
  403681:	mov    %r9,0x48(%rsp)
  403686:	xor    %r8d,%r8d
  403689:	mov    %rdx,0x18(%rsp)
  40368e:	movl   $0x8,0x8(%rsp)
  403696:	xor    %r9d,%r9d
  403699:	addq   $0x8,0x10(%rsp)
  40369f:	pushq  $0x0
  4036a1:	pushq  $0x0
  4036a3:	pushq  $0x0
  4036a5:	pushq  $0x0
  4036a7:	mov    0x30(%rsp),%rsi
  4036ac:	mov    (%rsi),%rdx
  4036af:	mov    %rdi,%rsi
  4036b2:	mov    0x23eae7(%rip),%rdi        # 6421a0 <stderr@@GLIBC_2.2.5>
  4036b9:	callq  401220 <fprintf@plt>
  4036be:	add    $0x20,%rsp
  4036c2:	mov    $0x1,%edi
  4036c7:	callq  401340 <exit@plt>
  4036cc:	nopl   0x0(%rax)

00000000004036d0 <Allocate_Image>:
  4036d0:	push   %rbp
  4036d1:	push   %rbx
  4036d2:	mov    %rsi,%rbp
  4036d5:	mov    %rdi,%rbx
  4036d8:	xor    %eax,%eax
  4036da:	mov    $0x418e98,%edi
  4036df:	sub    $0x8,%rsp
  4036e3:	callq  401170 <printf@plt>
  4036e8:	mov    %rbp,%rdi
  4036eb:	callq  401270 <malloc@plt>
  4036f0:	test   %rax,%rax
  4036f3:	mov    %rax,(%rbx)
  4036f6:	je     403801 <Allocate_Image+0x131>
  4036fc:	xor    %edx,%edx
  4036fe:	test   %rbp,%rbp
  403701:	jle    4037df <Allocate_Image+0x10f>
  403707:	lea    -0x1(%rbp),%rcx
  40370b:	and    $0x7,%ecx
  40370e:	je     4037d2 <Allocate_Image+0x102>
  403714:	cmp    $0x1,%rcx
  403718:	movb   $0x0,(%rax)
  40371b:	mov    $0x1,%edx
  403720:	mov    (%rbx),%rax
  403723:	je     4037d2 <Allocate_Image+0x102>
  403729:	cmp    $0x2,%rcx
  40372d:	je     403777 <Allocate_Image+0xa7>
  40372f:	cmp    $0x3,%rcx
  403733:	je     40376c <Allocate_Image+0x9c>
  403735:	cmp    $0x4,%rcx
  403739:	je     403761 <Allocate_Image+0x91>
  40373b:	cmp    $0x5,%rcx
  40373f:	je     403756 <Allocate_Image+0x86>
  403741:	cmp    $0x6,%rcx
  403745:	jne    4037f0 <Allocate_Image+0x120>
  40374b:	movb   $0x0,(%rax,%rdx,1)
  40374f:	mov    (%rbx),%rax
  403752:	add    $0x1,%rdx
  403756:	movb   $0x0,(%rax,%rdx,1)
  40375a:	mov    (%rbx),%rax
  40375d:	add    $0x1,%rdx
  403761:	movb   $0x0,(%rax,%rdx,1)
  403765:	mov    (%rbx),%rax
  403768:	add    $0x1,%rdx
  40376c:	movb   $0x0,(%rax,%rdx,1)
  403770:	mov    (%rbx),%rax
  403773:	add    $0x1,%rdx
  403777:	movb   $0x0,(%rax,%rdx,1)
  40377b:	mov    (%rbx),%rax
  40377e:	add    $0x1,%rdx
  403782:	movb   $0x0,(%rax,%rdx,1)
  403786:	lea    0x1(%rdx),%rax
  40378a:	cmp    %rax,%rbp
  40378d:	je     4037df <Allocate_Image+0x10f>
  40378f:	mov    (%rbx),%rsi
  403792:	movb   $0x0,0x1(%rsi,%rdx,1)
  403797:	mov    (%rbx),%rdi
  40379a:	movb   $0x0,0x2(%rdi,%rdx,1)
  40379f:	mov    (%rbx),%r8
  4037a2:	movb   $0x0,0x3(%r8,%rdx,1)
  4037a8:	mov    (%rbx),%r9
  4037ab:	movb   $0x0,0x4(%r9,%rdx,1)
  4037b1:	mov    (%rbx),%r10
  4037b4:	movb   $0x0,0x5(%r10,%rdx,1)
  4037ba:	mov    (%rbx),%r11
  4037bd:	movb   $0x0,0x6(%r11,%rdx,1)
  4037c3:	mov    (%rbx),%rcx
  4037c6:	movb   $0x0,0x7(%rcx,%rdx,1)
  4037cb:	mov    (%rbx),%rax
  4037ce:	add    $0x8,%rdx
  4037d2:	movb   $0x0,(%rax,%rdx,1)
  4037d6:	lea    0x1(%rdx),%rax
  4037da:	cmp    %rax,%rbp
  4037dd:	jne    40378f <Allocate_Image+0xbf>
  4037df:	add    $0x8,%rsp
  4037e3:	pop    %rbx
  4037e4:	pop    %rbp
  4037e5:	retq   
  4037e6:	nopw   %cs:0x0(%rax,%rax,1)
  4037f0:	movb   $0x0,(%rax,%rdx,1)
  4037f4:	mov    $0x2,%edx
  4037f9:	mov    (%rbx),%rax
  4037fc:	jmpq   40374b <Allocate_Image+0x7b>
  403801:	sub    $0x8,%rsp
  403805:	xor    %r9d,%r9d
  403808:	xor    %r8d,%r8d
  40380b:	pushq  $0x0
  40380d:	pushq  $0x0
  40380f:	xor    %ecx,%ecx
  403811:	pushq  $0x0
  403813:	xor    %edx,%edx
  403815:	xor    %esi,%esi
  403817:	mov    $0x418ec0,%edi
  40381c:	xor    %eax,%eax
  40381e:	callq  403650 <Error>
  403823:	nopl   (%rax)
  403826:	nopw   %cs:0x0(%rax,%rax,1)

0000000000403830 <Allocate_MImage>:
  403830:	push   %rbp
  403831:	push   %rbx
  403832:	mov    %rsi,%rbp
  403835:	mov    %rdi,%rbx
  403838:	xor    %eax,%eax
  40383a:	mov    $0x418e98,%edi
  40383f:	sub    $0x8,%rsp
  403843:	callq  401170 <printf@plt>
  403848:	mov    %rbp,%rdi
  40384b:	callq  401270 <malloc@plt>
  403850:	test   %rax,%rax
  403853:	mov    %rax,(%rbx)
  403856:	je     403961 <Allocate_MImage+0x131>
  40385c:	xor    %edx,%edx
  40385e:	test   %rbp,%rbp
  403861:	jle    40393f <Allocate_MImage+0x10f>
  403867:	lea    -0x1(%rbp),%rcx
  40386b:	and    $0x7,%ecx
  40386e:	je     403932 <Allocate_MImage+0x102>
  403874:	cmp    $0x1,%rcx
  403878:	movb   $0x0,(%rax)
  40387b:	mov    $0x1,%edx
  403880:	mov    (%rbx),%rax
  403883:	je     403932 <Allocate_MImage+0x102>
  403889:	cmp    $0x2,%rcx
  40388d:	je     4038d7 <Allocate_MImage+0xa7>
  40388f:	cmp    $0x3,%rcx
  403893:	je     4038cc <Allocate_MImage+0x9c>
  403895:	cmp    $0x4,%rcx
  403899:	je     4038c1 <Allocate_MImage+0x91>
  40389b:	cmp    $0x5,%rcx
  40389f:	je     4038b6 <Allocate_MImage+0x86>
  4038a1:	cmp    $0x6,%rcx
  4038a5:	jne    403950 <Allocate_MImage+0x120>
  4038ab:	movb   $0x0,(%rax,%rdx,1)
  4038af:	mov    (%rbx),%rax
  4038b2:	add    $0x1,%rdx
  4038b6:	movb   $0x0,(%rax,%rdx,1)
  4038ba:	mov    (%rbx),%rax
  4038bd:	add    $0x1,%rdx
  4038c1:	movb   $0x0,(%rax,%rdx,1)
  4038c5:	mov    (%rbx),%rax
  4038c8:	add    $0x1,%rdx
  4038cc:	movb   $0x0,(%rax,%rdx,1)
  4038d0:	mov    (%rbx),%rax
  4038d3:	add    $0x1,%rdx
  4038d7:	movb   $0x0,(%rax,%rdx,1)
  4038db:	mov    (%rbx),%rax
  4038de:	add    $0x1,%rdx
  4038e2:	movb   $0x0,(%rax,%rdx,1)
  4038e6:	lea    0x1(%rdx),%rax
  4038ea:	cmp    %rax,%rbp
  4038ed:	je     40393f <Allocate_MImage+0x10f>
  4038ef:	mov    (%rbx),%rsi
  4038f2:	movb   $0x0,0x1(%rsi,%rdx,1)
  4038f7:	mov    (%rbx),%rdi
  4038fa:	movb   $0x0,0x2(%rdi,%rdx,1)
  4038ff:	mov    (%rbx),%r8
  403902:	movb   $0x0,0x3(%r8,%rdx,1)
  403908:	mov    (%rbx),%r9
  40390b:	movb   $0x0,0x4(%r9,%rdx,1)
  403911:	mov    (%rbx),%r10
  403914:	movb   $0x0,0x5(%r10,%rdx,1)
  40391a:	mov    (%rbx),%r11
  40391d:	movb   $0x0,0x6(%r11,%rdx,1)
  403923:	mov    (%rbx),%rcx
  403926:	movb   $0x0,0x7(%rcx,%rdx,1)
  40392b:	mov    (%rbx),%rax
  40392e:	add    $0x8,%rdx
  403932:	movb   $0x0,(%rax,%rdx,1)
  403936:	lea    0x1(%rdx),%rax
  40393a:	cmp    %rax,%rbp
  40393d:	jne    4038ef <Allocate_MImage+0xbf>
  40393f:	add    $0x8,%rsp
  403943:	pop    %rbx
  403944:	pop    %rbp
  403945:	retq   
  403946:	nopw   %cs:0x0(%rax,%rax,1)
  403950:	movb   $0x0,(%rax,%rdx,1)
  403954:	mov    $0x2,%edx
  403959:	mov    (%rbx),%rax
  40395c:	jmpq   4038ab <Allocate_MImage+0x7b>
  403961:	mov    $0x418ec0,%edi
  403966:	xor    %eax,%eax
  403968:	callq  403650 <Error>
  40396d:	nopl   (%rax)

0000000000403970 <Lallocate_Image>:
  403970:	push   %rbp
  403971:	push   %rbx
  403972:	mov    %rdi,%rbp
  403975:	mov    %rsi,%rbx
  403978:	mov    $0x418e98,%edi
  40397d:	xor    %eax,%eax
  40397f:	sub    $0x8,%rsp
  403983:	callq  401170 <printf@plt>
  403988:	mov    $0x1,%esi
  40398d:	mov    %rbx,%rdi
  403990:	callq  401210 <calloc@plt>
  403995:	test   %rax,%rax
  403998:	mov    %rax,0x0(%rbp)
  40399c:	je     4039a5 <Lallocate_Image+0x35>
  40399e:	add    $0x8,%rsp
  4039a2:	pop    %rbx
  4039a3:	pop    %rbp
  4039a4:	retq   
  4039a5:	mov    $0x418ec0,%edi
  4039aa:	callq  403650 <Error>
  4039af:	nop

00000000004039b0 <Store_Image>:
  4039b0:	push   %rbx
  4039b1:	mov    %rdi,%rsi
  4039b4:	mov    $0x1,%ecx
  4039b9:	mov    $0x1,%ebx
  4039be:	sub    $0xe0,%rsp
  4039c5:	mov    0x240a5c(%rip),%rdx        # 644428 <image_len+0x8>
  4039cc:	mov    0x240a4d(%rip),%rax        # 644420 <image_len>
  4039d3:	lea    0x10(%rsp),%rdi
  4039d8:	mov    %cx,0xe(%rsp)
  4039dd:	mov    %bx,0x8(%rsp)
  4039e2:	mov    %dx,0xc(%rsp)
  4039e7:	mov    %ax,0xa(%rsp)
  4039ec:	callq  401140 <stpcpy@plt>
  4039f1:	lea    0x10(%rsp),%rdi
  4039f6:	movl   $0x7869702e,(%rax)
  4039fc:	movb   $0x0,0x4(%rax)
  403a00:	callq  403140 <Create_File>
  403a05:	lea    0x8(%rsp),%rsi
  403a0a:	mov    %eax,%edi
  403a0c:	mov    $0x2,%edx
  403a11:	mov    %eax,%ebx
  403a13:	callq  403270 <Write_Shorts>
  403a18:	lea    0xa(%rsp),%rsi
  403a1d:	mov    %ebx,%edi
  403a1f:	mov    $0x6,%edx
  403a24:	callq  403270 <Write_Shorts>
  403a29:	mov    %ebx,%edi
  403a2b:	mov    $0x4,%edx
  403a30:	mov    $0x642300,%esi
  403a35:	callq  403320 <Write_Longs>
  403a3a:	movslq 0x23e8bf(%rip),%rdx        # 642300 <image_length>
  403a41:	mov    0x23e898(%rip),%rsi        # 6422e0 <image_address>
  403a48:	mov    %ebx,%edi
  403a4a:	callq  4031c0 <Write_Bytes>
  403a4f:	mov    %ebx,%edi
  403a51:	callq  4035e0 <Close_File>
  403a56:	add    $0xe0,%rsp
  403a5d:	pop    %rbx
  403a5e:	retq   
  403a5f:	nop

0000000000403a60 <Allocate_Shading_Table>:
  403a60:	push   %rbp
  403a61:	push   %rbx
  403a62:	mov    %rsi,%rbp
  403a65:	mov    %rdi,%rbx
  403a68:	xor    %eax,%eax
  403a6a:	mov    $0x418ee8,%edi
  403a6f:	sub    $0x8,%rsp
  403a73:	callq  401170 <printf@plt>
  403a78:	mov    %rbp,%rdi
  403a7b:	callq  401270 <malloc@plt>
  403a80:	test   %rax,%rax
  403a83:	mov    %rax,(%rbx)
  403a86:	je     403b91 <Allocate_Shading_Table+0x131>
  403a8c:	xor    %edx,%edx
  403a8e:	test   %rbp,%rbp
  403a91:	jle    403b6f <Allocate_Shading_Table+0x10f>
  403a97:	lea    -0x1(%rbp),%rcx
  403a9b:	and    $0x7,%ecx
  403a9e:	je     403b62 <Allocate_Shading_Table+0x102>
  403aa4:	cmp    $0x1,%rcx
  403aa8:	movb   $0x0,(%rax)
  403aab:	mov    $0x1,%edx
  403ab0:	mov    (%rbx),%rax
  403ab3:	je     403b62 <Allocate_Shading_Table+0x102>
  403ab9:	cmp    $0x2,%rcx
  403abd:	je     403b07 <Allocate_Shading_Table+0xa7>
  403abf:	cmp    $0x3,%rcx
  403ac3:	je     403afc <Allocate_Shading_Table+0x9c>
  403ac5:	cmp    $0x4,%rcx
  403ac9:	je     403af1 <Allocate_Shading_Table+0x91>
  403acb:	cmp    $0x5,%rcx
  403acf:	je     403ae6 <Allocate_Shading_Table+0x86>
  403ad1:	cmp    $0x6,%rcx
  403ad5:	jne    403b80 <Allocate_Shading_Table+0x120>
  403adb:	movb   $0x0,(%rax,%rdx,1)
  403adf:	mov    (%rbx),%rax
  403ae2:	add    $0x1,%rdx
  403ae6:	movb   $0x0,(%rax,%rdx,1)
  403aea:	mov    (%rbx),%rax
  403aed:	add    $0x1,%rdx
  403af1:	movb   $0x0,(%rax,%rdx,1)
  403af5:	mov    (%rbx),%rax
  403af8:	add    $0x1,%rdx
  403afc:	movb   $0x0,(%rax,%rdx,1)
  403b00:	mov    (%rbx),%rax
  403b03:	add    $0x1,%rdx
  403b07:	movb   $0x0,(%rax,%rdx,1)
  403b0b:	mov    (%rbx),%rax
  403b0e:	add    $0x1,%rdx
  403b12:	movb   $0x0,(%rax,%rdx,1)
  403b16:	lea    0x1(%rdx),%rax
  403b1a:	cmp    %rax,%rbp
  403b1d:	je     403b6f <Allocate_Shading_Table+0x10f>
  403b1f:	mov    (%rbx),%rsi
  403b22:	movb   $0x0,0x1(%rsi,%rdx,1)
  403b27:	mov    (%rbx),%rdi
  403b2a:	movb   $0x0,0x2(%rdi,%rdx,1)
  403b2f:	mov    (%rbx),%r8
  403b32:	movb   $0x0,0x3(%r8,%rdx,1)
  403b38:	mov    (%rbx),%r9
  403b3b:	movb   $0x0,0x4(%r9,%rdx,1)
  403b41:	mov    (%rbx),%r10
  403b44:	movb   $0x0,0x5(%r10,%rdx,1)
  403b4a:	mov    (%rbx),%r11
  403b4d:	movb   $0x0,0x6(%r11,%rdx,1)
  403b53:	mov    (%rbx),%rcx
  403b56:	movb   $0x0,0x7(%rcx,%rdx,1)
  403b5b:	mov    (%rbx),%rax
  403b5e:	add    $0x8,%rdx
  403b62:	movb   $0x0,(%rax,%rdx,1)
  403b66:	lea    0x1(%rdx),%rax
  403b6a:	cmp    %rax,%rbp
  403b6d:	jne    403b1f <Allocate_Shading_Table+0xbf>
  403b6f:	add    $0x8,%rsp
  403b73:	pop    %rbx
  403b74:	pop    %rbp
  403b75:	retq   
  403b76:	nopw   %cs:0x0(%rax,%rax,1)
  403b80:	movb   $0x0,(%rax,%rdx,1)
  403b84:	mov    $0x2,%edx
  403b89:	mov    (%rbx),%rax
  403b8c:	jmpq   403adb <Allocate_Shading_Table+0x7b>
  403b91:	mov    $0x418f20,%edi
  403b96:	xor    %eax,%eax
  403b98:	callq  403650 <Error>
  403b9d:	nopl   (%rax)

0000000000403ba0 <Init_Decomposition>:
  403ba0:	mov    0x2408a9(%rip),%rax        # 644450 <num_nodes>
  403ba7:	cmp    $0x1,%rax
  403bab:	je     404110 <Init_Decomposition+0x570>
  403bb1:	pxor   %xmm4,%xmm4
  403bb5:	push   %rbp
  403bb6:	push   %rbx
  403bb7:	pxor   %xmm3,%xmm3
  403bbb:	sub    $0x2028,%rsp
  403bc2:	cvtsi2sd %rax,%xmm4
  403bc7:	ucomisd %xmm4,%xmm3
  403bcb:	sqrtsd %xmm4,%xmm1
  403bcf:	ja     4044c8 <Init_Decomposition+0x928>
  403bd5:	cvttsd2si %xmm1,%rbp
  403bda:	movapd %xmm4,%xmm0
  403bde:	movsd  0x155ea(%rip),%xmm1        # 4191d0 <__dso_handle+0x408>
  403be6:	movsd  %xmm3,0x8(%rsp)
  403bec:	movsd  %xmm2,(%rsp)
  403bf1:	movsd  %xmm4,0x10(%rsp)
  403bf7:	callq  4011d0 <pow@plt>
  403bfc:	movq   $0x1,0x20(%rsp)
  403c05:	cvttsd2si %xmm0,%rdx
  403c0a:	movsd  (%rsp),%xmm2
  403c0f:	movsd  0x8(%rsp),%xmm3
  403c15:	cmp    $0x2,%rbp
  403c19:	jle    404440 <Init_Decomposition+0x8a0>
  403c1f:	cmp    $0x1,%rdx
  403c23:	mov    0x240826(%rip),%rdi        # 644450 <num_nodes>
  403c2a:	movsd  0x10(%rsp),%xmm8
  403c31:	jg     404132 <Init_Decomposition+0x592>
  403c37:	mov    $0x1,%esi
  403c3c:	mov    $0x2,%ecx
  403c41:	pxor   %xmm4,%xmm4
  403c45:	movapd %xmm8,%xmm0
  403c4a:	pxor   %xmm5,%xmm5
  403c4e:	mov    %rcx,%r8
  403c51:	not    %r8
  403c54:	cvtsi2sd %rcx,%xmm4
  403c59:	add    %rbp,%r8
  403c5c:	and    $0x3,%r8d
  403c60:	divsd  %xmm4,%xmm0
  403c64:	cvttsd2si %xmm0,%r10
  403c69:	movapd %xmm0,%xmm6
  403c6d:	cvtsi2sd %r10,%xmm5
  403c72:	subsd  %xmm5,%xmm6
  403c76:	ucomisd %xmm3,%xmm6
  403c7a:	jp     403c87 <Init_Decomposition+0xe7>
  403c7c:	jne    403c87 <Init_Decomposition+0xe7>
  403c7e:	mov    %rcx,0x20(%rsp,%rsi,8)
  403c83:	add    $0x1,%rsi
  403c87:	add    $0x1,%rcx
  403c8b:	cmp    %rbp,%rcx
  403c8e:	jge    403e83 <Init_Decomposition+0x2e3>
  403c94:	test   %r8,%r8
  403c97:	je     403d77 <Init_Decomposition+0x1d7>
  403c9d:	cmp    $0x1,%r8
  403ca1:	je     403d2c <Init_Decomposition+0x18c>
  403ca7:	cmp    $0x2,%r8
  403cab:	je     403ce9 <Init_Decomposition+0x149>
  403cad:	pxor   %xmm9,%xmm9
  403cb2:	movapd %xmm8,%xmm0
  403cb7:	pxor   %xmm10,%xmm10
  403cbc:	cvtsi2sd %rcx,%xmm9
  403cc1:	divsd  %xmm9,%xmm0
  403cc6:	cvttsd2si %xmm0,%r9
  403ccb:	movapd %xmm0,%xmm7
  403ccf:	cvtsi2sd %r9,%xmm10
  403cd4:	subsd  %xmm10,%xmm7
  403cd9:	ucomisd %xmm3,%xmm7
  403cdd:	jp     403ce5 <Init_Decomposition+0x145>
  403cdf:	je     404460 <Init_Decomposition+0x8c0>
  403ce5:	add    $0x1,%rcx
  403ce9:	pxor   %xmm11,%xmm11
  403cee:	movapd %xmm8,%xmm0
  403cf3:	pxor   %xmm13,%xmm13
  403cf8:	cvtsi2sd %rcx,%xmm11
  403cfd:	divsd  %xmm11,%xmm0
  403d02:	cvttsd2si %xmm0,%r11
  403d07:	movapd %xmm0,%xmm12
  403d0c:	cvtsi2sd %r11,%xmm13
  403d11:	subsd  %xmm13,%xmm12
  403d16:	ucomisd %xmm3,%xmm12
  403d1b:	jp     403d28 <Init_Decomposition+0x188>
  403d1d:	jne    403d28 <Init_Decomposition+0x188>
  403d1f:	mov    %rcx,0x20(%rsp,%rsi,8)
  403d24:	add    $0x1,%rsi
  403d28:	add    $0x1,%rcx
  403d2c:	pxor   %xmm14,%xmm14
  403d31:	movapd %xmm8,%xmm0
  403d36:	pxor   %xmm1,%xmm1
  403d3a:	cvtsi2sd %rcx,%xmm14
  403d3f:	divsd  %xmm14,%xmm0
  403d44:	cvttsd2si %xmm0,%rax
  403d49:	movapd %xmm0,%xmm15
  403d4e:	cvtsi2sd %rax,%xmm1
  403d53:	subsd  %xmm1,%xmm15
  403d58:	ucomisd %xmm3,%xmm15
  403d5d:	jp     403d6a <Init_Decomposition+0x1ca>
  403d5f:	jne    403d6a <Init_Decomposition+0x1ca>
  403d61:	mov    %rcx,0x20(%rsp,%rsi,8)
  403d66:	add    $0x1,%rsi
  403d6a:	add    $0x1,%rcx
  403d6e:	cmp    %rbp,%rcx
  403d71:	jge    403e83 <Init_Decomposition+0x2e3>
  403d77:	pxor   %xmm4,%xmm4
  403d7b:	movapd %xmm8,%xmm0
  403d80:	pxor   %xmm5,%xmm5
  403d84:	cvtsi2sd %rcx,%xmm4
  403d89:	divsd  %xmm4,%xmm0
  403d8d:	cvttsd2si %xmm0,%rdx
  403d92:	movapd %xmm0,%xmm6
  403d96:	cvtsi2sd %rdx,%xmm5
  403d9b:	subsd  %xmm5,%xmm6
  403d9f:	ucomisd %xmm3,%xmm6
  403da3:	jp     403db0 <Init_Decomposition+0x210>
  403da5:	jne    403db0 <Init_Decomposition+0x210>
  403da7:	mov    %rcx,0x20(%rsp,%rsi,8)
  403dac:	add    $0x1,%rsi
  403db0:	pxor   %xmm9,%xmm9
  403db5:	add    $0x1,%rcx
  403db9:	movapd %xmm8,%xmm0
  403dbe:	pxor   %xmm10,%xmm10
  403dc3:	cvtsi2sd %rcx,%xmm9
  403dc8:	divsd  %xmm9,%xmm0
  403dcd:	cvttsd2si %xmm0,%r8
  403dd2:	movapd %xmm0,%xmm7
  403dd6:	cvtsi2sd %r8,%xmm10
  403ddb:	subsd  %xmm10,%xmm7
  403de0:	ucomisd %xmm3,%xmm7
  403de4:	jp     403df1 <Init_Decomposition+0x251>
  403de6:	jne    403df1 <Init_Decomposition+0x251>
  403de8:	mov    %rcx,0x20(%rsp,%rsi,8)
  403ded:	add    $0x1,%rsi
  403df1:	pxor   %xmm11,%xmm11
  403df6:	lea    0x1(%rcx),%r10
  403dfa:	movapd %xmm8,%xmm0
  403dff:	pxor   %xmm13,%xmm13
  403e04:	cvtsi2sd %r10,%xmm11
  403e09:	divsd  %xmm11,%xmm0
  403e0e:	cvttsd2si %xmm0,%r9
  403e13:	movapd %xmm0,%xmm12
  403e18:	cvtsi2sd %r9,%xmm13
  403e1d:	subsd  %xmm13,%xmm12
  403e22:	ucomisd %xmm3,%xmm12
  403e27:	jp     403e34 <Init_Decomposition+0x294>
  403e29:	jne    403e34 <Init_Decomposition+0x294>
  403e2b:	mov    %r10,0x20(%rsp,%rsi,8)
  403e30:	add    $0x1,%rsi
  403e34:	pxor   %xmm14,%xmm14
  403e39:	lea    0x2(%rcx),%r11
  403e3d:	movapd %xmm8,%xmm0
  403e42:	pxor   %xmm1,%xmm1
  403e46:	cvtsi2sd %r11,%xmm14
  403e4b:	divsd  %xmm14,%xmm0
  403e50:	cvttsd2si %xmm0,%rax
  403e55:	movapd %xmm0,%xmm15
  403e5a:	cvtsi2sd %rax,%xmm1
  403e5f:	subsd  %xmm1,%xmm15
  403e64:	ucomisd %xmm3,%xmm15
  403e69:	jp     403e76 <Init_Decomposition+0x2d6>
  403e6b:	jne    403e76 <Init_Decomposition+0x2d6>
  403e6d:	mov    %r11,0x20(%rsp,%rsi,8)
  403e72:	add    $0x1,%rsi
  403e76:	add    $0x3,%rcx
  403e7a:	cmp    %rbp,%rcx
  403e7d:	jl     403d77 <Init_Decomposition+0x1d7>
  403e83:	mov    0x18(%rsp,%rsi,8),%rcx
  403e88:	mov    %rdi,%rax
  403e8b:	cqto   
  403e8d:	idiv   %rcx
  403e90:	mov    %rcx,(%rsp)
  403e94:	sqrtsd %xmm2,%xmm4
  403e98:	ucomisd %xmm2,%xmm3
  403e9c:	movq   (%rsp),%xmm8
  403ea2:	mov    %rax,(%rsp)
  403ea6:	movhps (%rsp),%xmm8
  403eab:	movaps %xmm8,0x2405ad(%rip)        # 644460 <image_section>
  403eb3:	ja     404498 <Init_Decomposition+0x8f8>
  403eb9:	cvttsd2si %xmm4,%rbp
  403ebe:	cmp    $0x2,%rbp
  403ec2:	jle    404458 <Init_Decomposition+0x8b8>
  403ec8:	mov    $0x2,%r10d
  403ece:	mov    %rbp,%rdi
  403ed1:	mov    $0x1,%r8d
  403ed7:	sub    %r10,%rdi
  403eda:	and    $0x3,%edi
  403edd:	je     403fbf <Init_Decomposition+0x41f>
  403ee3:	cmp    $0x1,%rdi
  403ee7:	je     403f74 <Init_Decomposition+0x3d4>
  403eed:	cmp    $0x2,%rdi
  403ef1:	je     403f39 <Init_Decomposition+0x399>
  403ef3:	pxor   %xmm5,%xmm5
  403ef7:	movapd %xmm2,%xmm0
  403efb:	pxor   %xmm9,%xmm9
  403f00:	cvtsi2sd %r10,%xmm5
  403f05:	divsd  %xmm5,%xmm0
  403f09:	cvttsd2si %xmm0,%rsi
  403f0e:	movapd %xmm0,%xmm6
  403f12:	cvtsi2sd %rsi,%xmm9
  403f17:	subsd  %xmm9,%xmm6
  403f1c:	ucomisd %xmm3,%xmm6
  403f20:	jp     403f33 <Init_Decomposition+0x393>
  403f22:	jne    403f33 <Init_Decomposition+0x393>
  403f24:	movq   $0x2,0x28(%rsp)
  403f2d:	mov    $0x2,%r8d
  403f33:	mov    $0x3,%r10d
  403f39:	pxor   %xmm10,%xmm10
  403f3e:	movapd %xmm2,%xmm0
  403f42:	pxor   %xmm11,%xmm11
  403f47:	cvtsi2sd %r10,%xmm10
  403f4c:	divsd  %xmm10,%xmm0
  403f51:	cvttsd2si %xmm0,%rcx
  403f56:	movapd %xmm0,%xmm7
  403f5a:	cvtsi2sd %rcx,%xmm11
  403f5f:	subsd  %xmm11,%xmm7
  403f64:	ucomisd %xmm3,%xmm7
  403f68:	jp     403f70 <Init_Decomposition+0x3d0>
  403f6a:	je     404430 <Init_Decomposition+0x890>
  403f70:	add    $0x1,%r10
  403f74:	pxor   %xmm12,%xmm12
  403f79:	movapd %xmm2,%xmm0
  403f7d:	pxor   %xmm14,%xmm14
  403f82:	cvtsi2sd %r10,%xmm12
  403f87:	divsd  %xmm12,%xmm0
  403f8c:	cvttsd2si %xmm0,%r9
  403f91:	movapd %xmm0,%xmm13
  403f96:	cvtsi2sd %r9,%xmm14
  403f9b:	subsd  %xmm14,%xmm13
  403fa0:	ucomisd %xmm3,%xmm13
  403fa5:	jp     403fb2 <Init_Decomposition+0x412>
  403fa7:	jne    403fb2 <Init_Decomposition+0x412>
  403fa9:	mov    %r10,0x20(%rsp,%r8,8)
  403fae:	add    $0x1,%r8
  403fb2:	add    $0x1,%r10
  403fb6:	cmp    %r10,%rbp
  403fb9:	je     4040c8 <Init_Decomposition+0x528>
  403fbf:	pxor   %xmm15,%xmm15
  403fc4:	movapd %xmm2,%xmm0
  403fc8:	pxor   %xmm1,%xmm1
  403fcc:	cvtsi2sd %r10,%xmm15
  403fd1:	divsd  %xmm15,%xmm0
  403fd6:	cvttsd2si %xmm0,%r11
  403fdb:	movapd %xmm0,%xmm8
  403fe0:	cvtsi2sd %r11,%xmm1
  403fe5:	subsd  %xmm1,%xmm8
  403fea:	ucomisd %xmm3,%xmm8
  403fef:	jp     403ffc <Init_Decomposition+0x45c>
  403ff1:	jne    403ffc <Init_Decomposition+0x45c>
  403ff3:	mov    %r10,0x20(%rsp,%r8,8)
  403ff8:	add    $0x1,%r8
  403ffc:	pxor   %xmm4,%xmm4
  404000:	add    $0x1,%r10
  404004:	movapd %xmm2,%xmm0
  404008:	pxor   %xmm6,%xmm6
  40400c:	cvtsi2sd %r10,%xmm4
  404011:	divsd  %xmm4,%xmm0
  404015:	cvttsd2si %xmm0,%rax
  40401a:	movapd %xmm0,%xmm5
  40401e:	cvtsi2sd %rax,%xmm6
  404023:	subsd  %xmm6,%xmm5
  404027:	ucomisd %xmm3,%xmm5
  40402b:	jp     404038 <Init_Decomposition+0x498>
  40402d:	jne    404038 <Init_Decomposition+0x498>
  40402f:	mov    %r10,0x20(%rsp,%r8,8)
  404034:	add    $0x1,%r8
  404038:	pxor   %xmm9,%xmm9
  40403d:	lea    0x1(%r10),%rdx
  404041:	movapd %xmm2,%xmm0
  404045:	pxor   %xmm7,%xmm7
  404049:	cvtsi2sd %rdx,%xmm9
  40404e:	divsd  %xmm9,%xmm0
  404053:	cvttsd2si %xmm0,%rdi
  404058:	movapd %xmm0,%xmm10
  40405d:	cvtsi2sd %rdi,%xmm7
  404062:	subsd  %xmm7,%xmm10
  404067:	ucomisd %xmm3,%xmm10
  40406c:	jp     404079 <Init_Decomposition+0x4d9>
  40406e:	jne    404079 <Init_Decomposition+0x4d9>
  404070:	mov    %rdx,0x20(%rsp,%r8,8)
  404075:	add    $0x1,%r8
  404079:	pxor   %xmm11,%xmm11
  40407e:	lea    0x2(%r10),%rsi
  404082:	movapd %xmm2,%xmm0
  404086:	pxor   %xmm13,%xmm13
  40408b:	cvtsi2sd %rsi,%xmm11
  404090:	divsd  %xmm11,%xmm0
  404095:	cvttsd2si %xmm0,%rcx
  40409a:	movapd %xmm0,%xmm12
  40409f:	cvtsi2sd %rcx,%xmm13
  4040a4:	subsd  %xmm13,%xmm12
  4040a9:	ucomisd %xmm3,%xmm12
  4040ae:	jp     4040bb <Init_Decomposition+0x51b>
  4040b0:	jne    4040bb <Init_Decomposition+0x51b>
  4040b2:	mov    %rsi,0x20(%rsp,%r8,8)
  4040b7:	add    $0x1,%r8
  4040bb:	add    $0x3,%r10
  4040bf:	cmp    %r10,%rbp
  4040c2:	jne    403fbf <Init_Decomposition+0x41f>
  4040c8:	sub    $0x1,%r8
  4040cc:	cvttsd2si %xmm2,%rax
  4040d1:	mov    0x20(%rsp,%r8,8),%rbp
  4040d6:	mov    %rbx,%r8
  4040d9:	cmp    %rbx,%rbp
  4040dc:	cmovge %rbp,%rbx
  4040e0:	cmovle %rbp,%r8
  4040e4:	mov    %rbx,0x24034d(%rip)        # 644438 <voxel_section+0x8>
  4040eb:	mov    %r8,0x24033e(%rip)        # 644430 <voxel_section>
  4040f2:	cqto   
  4040f4:	idiv   %rbp
  4040f7:	mov    %rax,0x240342(%rip)        # 644440 <voxel_section+0x10>
  4040fe:	add    $0x2028,%rsp
  404105:	pop    %rbx
  404106:	pop    %rbp
  404107:	retq   
  404108:	nopl   0x0(%rax,%rax,1)
  404110:	movdqa 0x150a8(%rip),%xmm2        # 4191c0 <__dso_handle+0x3f8>
  404118:	movq   $0x1,0x24031d(%rip)        # 644440 <voxel_section+0x10>
  404123:	movaps %xmm2,0x240336(%rip)        # 644460 <image_section>
  40412a:	movaps %xmm2,0x2402ff(%rip)        # 644430 <voxel_section>
  404131:	retq   
  404132:	pxor   %xmm0,%xmm0
  404136:	mov    $0x2,%r10d
  40413c:	movapd %xmm8,%xmm6
  404141:	lea    -0x1(%rbp),%r8
  404145:	pxor   %xmm5,%xmm5
  404149:	mov    $0x1,%esi
  40414e:	cvtsi2sd %r10,%xmm0
  404153:	cmp    %rdx,%r8
  404156:	cmovg  %rdx,%r8
  40415a:	mov    %r8,%r9
  40415d:	sub    %r10,%r9
  404160:	and    $0x3,%r9d
  404164:	divsd  %xmm0,%xmm6
  404168:	cvttsd2si %xmm6,%r11
  40416d:	cvtsi2sd %r11,%xmm5
  404172:	subsd  %xmm5,%xmm6
  404176:	ucomisd %xmm3,%xmm6
  40417a:	jp     4041a2 <Init_Decomposition+0x602>
  40417c:	jne    4041a2 <Init_Decomposition+0x602>
  40417e:	mov    %rdi,%rax
  404181:	pxor   %xmm2,%xmm2
  404185:	cqto   
  404187:	movq   $0x2,0x28(%rsp)
  404190:	mov    $0x2,%esi
  404195:	idiv   %r10
  404198:	mov    $0x2,%ebx
  40419d:	cvtsi2sd %rax,%xmm2
  4041a2:	cmp    $0x3,%r8
  4041a6:	mov    $0x3,%ecx
  4041ab:	jl     404418 <Init_Decomposition+0x878>
  4041b1:	test   %r9,%r9
  4041b4:	je     4042bc <Init_Decomposition+0x71c>
  4041ba:	cmp    $0x1,%r9
  4041be:	je     40425d <Init_Decomposition+0x6bd>
  4041c4:	cmp    $0x2,%r9
  4041c8:	je     404206 <Init_Decomposition+0x666>
  4041ca:	pxor   %xmm9,%xmm9
  4041cf:	movapd %xmm8,%xmm0
  4041d4:	pxor   %xmm10,%xmm10
  4041d9:	cvtsi2sd %rcx,%xmm9
  4041de:	divsd  %xmm9,%xmm0
  4041e3:	cvttsd2si %xmm0,%r10
  4041e8:	movapd %xmm0,%xmm7
  4041ec:	cvtsi2sd %r10,%xmm10
  4041f1:	subsd  %xmm10,%xmm7
  4041f6:	ucomisd %xmm3,%xmm7
  4041fa:	jp     404202 <Init_Decomposition+0x662>
  4041fc:	je     404470 <Init_Decomposition+0x8d0>
  404202:	add    $0x1,%rcx
  404206:	pxor   %xmm11,%xmm11
  40420b:	movapd %xmm8,%xmm0
  404210:	pxor   %xmm13,%xmm13
  404215:	cvtsi2sd %rcx,%xmm11
  40421a:	divsd  %xmm11,%xmm0
  40421f:	cvttsd2si %xmm0,%r9
  404224:	movapd %xmm0,%xmm12
  404229:	cvtsi2sd %r9,%xmm13
  40422e:	subsd  %xmm13,%xmm12
  404233:	ucomisd %xmm3,%xmm12
  404238:	jp     404259 <Init_Decomposition+0x6b9>
  40423a:	jne    404259 <Init_Decomposition+0x6b9>
  40423c:	mov    %rdi,%rax
  40423f:	pxor   %xmm2,%xmm2
  404243:	cqto   
  404245:	mov    %rcx,0x20(%rsp,%rsi,8)
  40424a:	mov    %rcx,%rbx
  40424d:	idiv   %rcx
  404250:	add    $0x1,%rsi
  404254:	cvtsi2sd %rax,%xmm2
  404259:	add    $0x1,%rcx
  40425d:	pxor   %xmm14,%xmm14
  404262:	movapd %xmm8,%xmm0
  404267:	pxor   %xmm1,%xmm1
  40426b:	cvtsi2sd %rcx,%xmm14
  404270:	divsd  %xmm14,%xmm0
  404275:	cvttsd2si %xmm0,%r11
  40427a:	movapd %xmm0,%xmm15
  40427f:	cvtsi2sd %r11,%xmm1
  404284:	subsd  %xmm1,%xmm15
  404289:	ucomisd %xmm3,%xmm15
  40428e:	jp     4042af <Init_Decomposition+0x70f>
  404290:	jne    4042af <Init_Decomposition+0x70f>
  404292:	mov    %rdi,%rax
  404295:	pxor   %xmm2,%xmm2
  404299:	cqto   
  40429b:	mov    %rcx,0x20(%rsp,%rsi,8)
  4042a0:	mov    %rcx,%rbx
  4042a3:	idiv   %rcx
  4042a6:	add    $0x1,%rsi
  4042aa:	cvtsi2sd %rax,%xmm2
  4042af:	add    $0x1,%rcx
  4042b3:	cmp    %rcx,%r8
  4042b6:	jl     404418 <Init_Decomposition+0x878>
  4042bc:	pxor   %xmm4,%xmm4
  4042c0:	movapd %xmm8,%xmm0
  4042c5:	pxor   %xmm5,%xmm5
  4042c9:	cvtsi2sd %rcx,%xmm4
  4042ce:	divsd  %xmm4,%xmm0
  4042d2:	cvttsd2si %xmm0,%r10
  4042d7:	movapd %xmm0,%xmm6
  4042db:	cvtsi2sd %r10,%xmm5
  4042e0:	subsd  %xmm5,%xmm6
  4042e4:	ucomisd %xmm3,%xmm6
  4042e8:	jp     404309 <Init_Decomposition+0x769>
  4042ea:	jne    404309 <Init_Decomposition+0x769>
  4042ec:	mov    %rdi,%rax
  4042ef:	pxor   %xmm2,%xmm2
  4042f3:	cqto   
  4042f5:	mov    %rcx,0x20(%rsp,%rsi,8)
  4042fa:	mov    %rcx,%rbx
  4042fd:	idiv   %rcx
  404300:	add    $0x1,%rsi
  404304:	cvtsi2sd %rax,%xmm2
  404309:	pxor   %xmm9,%xmm9
  40430e:	add    $0x1,%rcx
  404312:	movapd %xmm8,%xmm0
  404317:	pxor   %xmm10,%xmm10
  40431c:	cvtsi2sd %rcx,%xmm9
  404321:	divsd  %xmm9,%xmm0
  404326:	cvttsd2si %xmm0,%r9
  40432b:	movapd %xmm0,%xmm7
  40432f:	cvtsi2sd %r9,%xmm10
  404334:	subsd  %xmm10,%xmm7
  404339:	ucomisd %xmm3,%xmm7
  40433d:	jp     40435e <Init_Decomposition+0x7be>
  40433f:	jne    40435e <Init_Decomposition+0x7be>
  404341:	mov    %rdi,%rax
  404344:	pxor   %xmm2,%xmm2
  404348:	cqto   
  40434a:	mov    %rcx,0x20(%rsp,%rsi,8)
  40434f:	mov    %rcx,%rbx
  404352:	idiv   %rcx
  404355:	add    $0x1,%rsi
  404359:	cvtsi2sd %rax,%xmm2
  40435e:	pxor   %xmm11,%xmm11
  404363:	lea    0x1(%rcx),%r11
  404367:	movapd %xmm8,%xmm0
  40436c:	pxor   %xmm13,%xmm13
  404371:	cvtsi2sd %r11,%xmm11
  404376:	divsd  %xmm11,%xmm0
  40437b:	cvttsd2si %xmm0,%r10
  404380:	movapd %xmm0,%xmm12
  404385:	cvtsi2sd %r10,%xmm13
  40438a:	subsd  %xmm13,%xmm12
  40438f:	ucomisd %xmm3,%xmm12
  404394:	jp     4043b5 <Init_Decomposition+0x815>
  404396:	jne    4043b5 <Init_Decomposition+0x815>
  404398:	mov    %rdi,%rax
  40439b:	pxor   %xmm2,%xmm2
  40439f:	cqto   
  4043a1:	mov    %r11,0x20(%rsp,%rsi,8)
  4043a6:	mov    %r11,%rbx
  4043a9:	idiv   %r11
  4043ac:	add    $0x1,%rsi
  4043b0:	cvtsi2sd %rax,%xmm2
  4043b5:	pxor   %xmm14,%xmm14
  4043ba:	lea    0x2(%rcx),%r9
  4043be:	movapd %xmm8,%xmm0
  4043c3:	pxor   %xmm1,%xmm1
  4043c7:	cvtsi2sd %r9,%xmm14
  4043cc:	divsd  %xmm14,%xmm0
  4043d1:	cvttsd2si %xmm0,%r11
  4043d6:	movapd %xmm0,%xmm15
  4043db:	cvtsi2sd %r11,%xmm1
  4043e0:	subsd  %xmm1,%xmm15
  4043e5:	ucomisd %xmm3,%xmm15
  4043ea:	jp     40440b <Init_Decomposition+0x86b>
  4043ec:	jne    40440b <Init_Decomposition+0x86b>
  4043ee:	mov    %rdi,%rax
  4043f1:	pxor   %xmm2,%xmm2
  4043f5:	cqto   
  4043f7:	mov    %r9,0x20(%rsp,%rsi,8)
  4043fc:	mov    %r9,%rbx
  4043ff:	idiv   %r9
  404402:	add    $0x1,%rsi
  404406:	cvtsi2sd %rax,%xmm2
  40440b:	add    $0x3,%rcx
  40440f:	cmp    %rcx,%r8
  404412:	jge    4042bc <Init_Decomposition+0x71c>
  404418:	cmp    %rcx,%rbp
  40441b:	jg     403c41 <Init_Decomposition+0xa1>
  404421:	jmpq   403e83 <Init_Decomposition+0x2e3>
  404426:	nopw   %cs:0x0(%rax,%rax,1)
  404430:	mov    %r10,0x20(%rsp,%r8,8)
  404435:	add    $0x1,%r8
  404439:	jmpq   403f70 <Init_Decomposition+0x3d0>
  40443e:	xchg   %ax,%ax
  404440:	mov    0x240009(%rip),%rax        # 644450 <num_nodes>
  404447:	mov    $0x1,%ecx
  40444c:	jmpq   403e90 <Init_Decomposition+0x2f0>
  404451:	nopl   0x0(%rax)
  404458:	xor    %r8d,%r8d
  40445b:	jmpq   4040cc <Init_Decomposition+0x52c>
  404460:	mov    %rcx,0x20(%rsp,%rsi,8)
  404465:	add    $0x1,%rsi
  404469:	jmpq   403ce5 <Init_Decomposition+0x145>
  40446e:	xchg   %ax,%ax
  404470:	mov    %rdi,%rax
  404473:	pxor   %xmm2,%xmm2
  404477:	cqto   
  404479:	movq   $0x3,0x20(%rsp,%rsi,8)
  404482:	mov    $0x3,%ebx
  404487:	idiv   %rcx
  40448a:	add    $0x1,%rsi
  40448e:	cvtsi2sd %rax,%xmm2
  404493:	jmpq   404202 <Init_Decomposition+0x662>
  404498:	movapd %xmm2,%xmm0
  40449c:	movsd  %xmm3,0x10(%rsp)
  4044a2:	movsd  %xmm4,0x8(%rsp)
  4044a8:	movsd  %xmm2,(%rsp)
  4044ad:	callq  401360 <sqrt@plt>
  4044b2:	movsd  0x10(%rsp),%xmm3
  4044b8:	movsd  0x8(%rsp),%xmm4
  4044be:	movsd  (%rsp),%xmm2
  4044c3:	jmpq   403eb9 <Init_Decomposition+0x319>
  4044c8:	movapd %xmm4,%xmm0
  4044cc:	movsd  %xmm3,0x18(%rsp)
  4044d2:	movsd  %xmm2,0x10(%rsp)
  4044d8:	movsd  %xmm1,0x8(%rsp)
  4044de:	movsd  %xmm4,(%rsp)
  4044e3:	callq  401360 <sqrt@plt>
  4044e8:	movsd  0x18(%rsp),%xmm3
  4044ee:	movsd  0x10(%rsp),%xmm2
  4044f4:	movsd  0x8(%rsp),%xmm1
  4044fa:	movsd  (%rsp),%xmm4
  4044ff:	jmpq   403bd5 <Init_Decomposition+0x35>
  404504:	xchg   %ax,%ax
  404506:	nopw   %cs:0x0(%rax,%rax,1)

0000000000404510 <WriteGrayscaleTIFF>:
  404510:	push   %r14
  404512:	push   %r13
  404514:	xor    %eax,%eax
  404516:	push   %r12
  404518:	push   %rbp
  404519:	mov    %rdx,%r12
  40451c:	push   %rbx
  40451d:	mov    %rsi,%r13
  404520:	mov    %rcx,%rbp
  404523:	mov    %r8,%rbx
  404526:	sub    $0x800,%rsp
  40452d:	lea    0xc8(%rsp),%rdx
  404535:	movsd  0x14c9b(%rip),%xmm1        # 4191d8 <__dso_handle+0x410>
  40453d:	nopl   (%rax)
  404540:	pxor   %xmm0,%xmm0
  404544:	lea    0x1(%rax),%rsi
  404548:	prefetcht0 (%rdx)
  40454b:	pxor   %xmm2,%xmm2
  40454f:	lea    0x2(%rax),%r9
  404553:	pxor   %xmm3,%xmm3
  404557:	lea    0x3(%rax),%r11
  40455b:	pxor   %xmm4,%xmm4
  40455f:	add    $0x40,%rdx
  404563:	cvtsi2sd %rax,%xmm0
  404568:	cvtsi2sd %rsi,%xmm2
  40456d:	pxor   %xmm5,%xmm5
  404571:	cvtsi2sd %r9,%xmm3
  404576:	cvtsi2sd %r11,%xmm4
  40457b:	pxor   %xmm6,%xmm6
  40457f:	pxor   %xmm7,%xmm7
  404583:	pxor   %xmm8,%xmm8
  404588:	mulsd  %xmm1,%xmm0
  40458c:	mulsd  %xmm1,%xmm2
  404590:	mulsd  %xmm1,%xmm3
  404594:	mulsd  %xmm1,%xmm4
  404598:	cvttsd2si %xmm0,%rcx
  40459d:	cvttsd2si %xmm2,%r8
  4045a2:	cvttsd2si %xmm3,%r10
  4045a7:	cvttsd2si %xmm4,%r14
  4045ac:	mov    %rcx,-0x108(%rdx)
  4045b3:	lea    0x4(%rax),%rcx
  4045b7:	mov    %r8,-0x100(%rdx)
  4045be:	lea    0x5(%rax),%r8
  4045c2:	mov    %r10,-0xf8(%rdx)
  4045c9:	lea    0x6(%rax),%r10
  4045cd:	mov    %r14,-0xf0(%rdx)
  4045d4:	lea    0x7(%rax),%r14
  4045d8:	add    $0x8,%rax
  4045dc:	cvtsi2sd %rcx,%xmm5
  4045e1:	cvtsi2sd %r8,%xmm6
  4045e6:	cvtsi2sd %r10,%xmm7
  4045eb:	cvtsi2sd %r14,%xmm8
  4045f0:	mulsd  %xmm1,%xmm5
  4045f4:	mulsd  %xmm1,%xmm6
  4045f8:	mulsd  %xmm1,%xmm7
  4045fc:	mulsd  %xmm1,%xmm8
  404601:	cvttsd2si %xmm5,%rsi
  404606:	cvttsd2si %xmm6,%r9
  40460b:	cvttsd2si %xmm7,%r11
  404610:	cvttsd2si %xmm8,%rcx
  404615:	mov    %rsi,-0xe8(%rdx)
  40461c:	mov    %r9,-0xe0(%rdx)
  404623:	mov    %r11,-0xd8(%rdx)
  40462a:	mov    %rcx,-0xd0(%rdx)
  404631:	cmp    $0xf8,%rax
  404637:	jne    404540 <WriteGrayscaleTIFF+0x30>
  40463d:	mov    $0xf8,%edx
  404642:	nopw   0x0(%rax,%rax,1)
  404648:	pxor   %xmm9,%xmm9
  40464d:	cvtsi2sd %rdx,%xmm9
  404652:	mulsd  %xmm1,%xmm9
  404657:	cvttsd2si %xmm9,%rax
  40465c:	mov    %rax,(%rsp,%rdx,8)
  404660:	add    $0x1,%rdx
  404664:	cmp    $0x100,%rdx
  40466b:	jne    404648 <WriteGrayscaleTIFF+0x138>
  40466d:	mov    $0x41915c,%esi
  404672:	callq  412f5e <TIFFOpen>
  404677:	mov    %rax,%r14
  40467a:	xor    %eax,%eax
  40467c:	test   %r14,%r14
  40467f:	je     404817 <WriteGrayscaleTIFF+0x307>
  404685:	mov    %r13,%rdx
  404688:	mov    $0x100,%esi
  40468d:	mov    %r14,%rdi
  404690:	callq  4105df <TIFFSetField>
  404695:	mov    %r12,%rdx
  404698:	mov    $0x101,%esi
  40469d:	mov    %r14,%rdi
  4046a0:	xor    %eax,%eax
  4046a2:	callq  4105df <TIFFSetField>
  4046a7:	mov    $0x8,%edx
  4046ac:	mov    $0x102,%esi
  4046b1:	mov    %r14,%rdi
  4046b4:	xor    %eax,%eax
  4046b6:	callq  4105df <TIFFSetField>
  4046bb:	mov    $0x1,%edx
  4046c0:	mov    $0x115,%esi
  4046c5:	mov    %r14,%rdi
  4046c8:	xor    %eax,%eax
  4046ca:	callq  4105df <TIFFSetField>
  4046cf:	mov    $0x1,%edx
  4046d4:	mov    $0x11c,%esi
  4046d9:	mov    %r14,%rdi
  4046dc:	xor    %eax,%eax
  4046de:	callq  4105df <TIFFSetField>
  4046e3:	mov    $0x5,%edx
  4046e8:	mov    $0x103,%esi
  4046ed:	mov    %r14,%rdi
  4046f0:	xor    %eax,%eax
  4046f2:	callq  4105df <TIFFSetField>
  4046f7:	mov    $0x4,%edx
  4046fc:	mov    $0x112,%esi
  404701:	mov    %r14,%rdi
  404704:	xor    %eax,%eax
  404706:	callq  4105df <TIFFSetField>
  40470b:	mov    $0x3,%edx
  404710:	mov    $0x106,%esi
  404715:	mov    %r14,%rdi
  404718:	xor    %eax,%eax
  40471a:	callq  4105df <TIFFSetField>
  40471f:	xor    %eax,%eax
  404721:	mov    %rsp,%r8
  404724:	mov    %rsp,%rcx
  404727:	mov    %rsp,%rdx
  40472a:	mov    $0x140,%esi
  40472f:	mov    %r14,%rdi
  404732:	callq  4105df <TIFFSetField>
  404737:	test   %r12,%r12
  40473a:	jle    40480a <WriteGrayscaleTIFF+0x2fa>
  404740:	mov    %r12,%rdi
  404743:	xor    %r13d,%r13d
  404746:	and    $0x3,%edi
  404749:	je     40479e <WriteGrayscaleTIFF+0x28e>
  40474b:	cmp    $0x1,%rdi
  40474f:	je     40477a <WriteGrayscaleTIFF+0x26a>
  404751:	cmp    $0x2,%rdi
  404755:	jne    404827 <WriteGrayscaleTIFF+0x317>
  40475b:	xor    %ecx,%ecx
  40475d:	mov    %r13d,%edx
  404760:	mov    %rbx,%rsi
  404763:	mov    %r14,%rdi
  404766:	add    %rbp,%rbx
  404769:	add    $0x1,%r13
  40476d:	callq  4139ac <TIFFWriteScanline>
  404772:	test   %eax,%eax
  404774:	je     404847 <WriteGrayscaleTIFF+0x337>
  40477a:	xor    %ecx,%ecx
  40477c:	mov    %r13d,%edx
  40477f:	mov    %rbx,%rsi
  404782:	mov    %r14,%rdi
  404785:	callq  4139ac <TIFFWriteScanline>
  40478a:	test   %eax,%eax
  40478c:	je     404847 <WriteGrayscaleTIFF+0x337>
  404792:	add    $0x1,%r13
  404796:	add    %rbp,%rbx
  404799:	cmp    %r13,%r12
  40479c:	je     40480a <WriteGrayscaleTIFF+0x2fa>
  40479e:	xor    %ecx,%ecx
  4047a0:	mov    %r13d,%edx
  4047a3:	mov    %rbx,%rsi
  4047a6:	mov    %r14,%rdi
  4047a9:	callq  4139ac <TIFFWriteScanline>
  4047ae:	test   %eax,%eax
  4047b0:	je     404847 <WriteGrayscaleTIFF+0x337>
  4047b6:	add    %rbp,%rbx
  4047b9:	lea    0x1(%r13),%rdx
  4047bd:	xor    %ecx,%ecx
  4047bf:	mov    %rbx,%rsi
  4047c2:	mov    %r14,%rdi
  4047c5:	callq  4139ac <TIFFWriteScanline>
  4047ca:	test   %eax,%eax
  4047cc:	je     404847 <WriteGrayscaleTIFF+0x337>
  4047ce:	add    %rbp,%rbx
  4047d1:	lea    0x2(%r13),%rdx
  4047d5:	xor    %ecx,%ecx
  4047d7:	mov    %rbx,%rsi
  4047da:	mov    %r14,%rdi
  4047dd:	callq  4139ac <TIFFWriteScanline>
  4047e2:	test   %eax,%eax
  4047e4:	je     404847 <WriteGrayscaleTIFF+0x337>
  4047e6:	add    %rbp,%rbx
  4047e9:	lea    0x3(%r13),%rdx
  4047ed:	xor    %ecx,%ecx
  4047ef:	mov    %rbx,%rsi
  4047f2:	mov    %r14,%rdi
  4047f5:	callq  4139ac <TIFFWriteScanline>
  4047fa:	test   %eax,%eax
  4047fc:	je     404847 <WriteGrayscaleTIFF+0x337>
  4047fe:	add    $0x4,%r13
  404802:	add    %rbp,%rbx
  404805:	cmp    %r13,%r12
  404808:	jne    40479e <WriteGrayscaleTIFF+0x28e>
  40480a:	mov    %r14,%rdi
  40480d:	callq  40da67 <TIFFClose>
  404812:	mov    $0x1,%eax
  404817:	add    $0x800,%rsp
  40481e:	pop    %rbx
  40481f:	pop    %rbp
  404820:	pop    %r12
  404822:	pop    %r13
  404824:	pop    %r14
  404826:	retq   
  404827:	xor    %ecx,%ecx
  404829:	xor    %edx,%edx
  40482b:	mov    %rbx,%rsi
  40482e:	mov    %r14,%rdi
  404831:	add    %rbp,%rbx
  404834:	mov    $0x1,%r13d
  40483a:	callq  4139ac <TIFFWriteScanline>
  40483f:	test   %eax,%eax
  404841:	jne    40475b <WriteGrayscaleTIFF+0x24b>
  404847:	mov    %r14,%rdi
  40484a:	callq  40da67 <TIFFClose>
  40484f:	add    $0x800,%rsp
  404856:	xor    %eax,%eax
  404858:	pop    %rbx
  404859:	pop    %rbp
  40485a:	pop    %r12
  40485c:	pop    %r13
  40485e:	pop    %r14
  404860:	retq   
  404861:	nopl   0x0(%rax,%rax,1)
  404866:	nopw   %cs:0x0(%rax,%rax,1)

0000000000404870 <Render_Loop>:
  404870:	push   %r15
  404872:	push   %r14
  404874:	push   %r13
  404876:	push   %r12
  404878:	push   %rbp
  404879:	push   %rbx
  40487a:	sub    $0x128,%rsp
  404881:	mov    0x23da50(%rip),%rax        # 6422d8 <Global>
  404888:	lea    0x2008e0(%rax),%rdi
  40488f:	callq  401380 <pthread_mutex_lock@plt>
  404894:	mov    0x23da3d(%rip),%rdx        # 6422d8 <Global>
  40489b:	mov    (%rdx),%r15
  40489e:	lea    0x2008e0(%rdx),%rdi
  4048a5:	lea    0x1(%r15),%rcx
  4048a9:	mov    %rcx,(%rdx)
  4048ac:	callq  401260 <pthread_mutex_unlock@plt>
  4048b1:	mov    0x23fb98(%rip),%rbx        # 644450 <num_nodes>
  4048b8:	pxor   %xmm0,%xmm0
  4048bc:	movss  0x14538(%rip),%xmm1        # 418dfc <__dso_handle+0x34>
  4048c4:	mov    %r15,%rax
  4048c7:	pxor   %xmm3,%xmm3
  4048cb:	cqto   
  4048cd:	cvtsi2ss %rbx,%xmm0
  4048d2:	cvtsi2ssl 0x23da26(%rip),%xmm3        # 642300 <image_length>
  4048da:	pxor   %xmm2,%xmm2
  4048de:	idiv   %rbx
  4048e1:	mov    %rdx,%r15
  4048e4:	divss  %xmm0,%xmm1
  4048e8:	mulss  %xmm1,%xmm3
  4048ec:	cvttss2si %xmm3,%r14
  4048f1:	cvtsi2ss %r14,%xmm2
  4048f6:	ucomiss %xmm2,%xmm3
  4048f9:	jp     4048fd <Render_Loop+0x8d>
  4048fb:	je     404901 <Render_Loop+0x91>
  4048fd:	add    $0x1,%r14
  404901:	pxor   %xmm4,%xmm4
  404905:	pxor   %xmm5,%xmm5
  404909:	cvtsi2ssq 0x23d9b6(%rip),%xmm4        # 6422c8 <mask_image_length>
  404912:	mulss  %xmm1,%xmm4
  404916:	cvttss2si %xmm4,%rsi
  40491b:	cvtsi2ss %rsi,%xmm5
  404920:	mov    %rsi,0x38(%rsp)
  404925:	ucomiss %xmm5,%xmm4
  404928:	jp     40492c <Render_Loop+0xbc>
  40492a:	je     404932 <Render_Loop+0xc2>
  40492c:	addq   $0x1,0x38(%rsp)
  404932:	mov    0x38(%rsp),%rbp
  404937:	mov    %r14,%rdi
  40493a:	mov    0x21a863(%rip),%r11d        # 61f1a4 <ROTATE_STEPS>
  404941:	imul   %r15,%rdi
  404945:	movq   $0x0,0x20(%rsp)
  40494e:	imul   %r15,%rbp
  404952:	mov    %rdi,(%rsp)
  404956:	mov    %rbp,0x10(%rsp)
  40495b:	mov    0x20(%rsp),%r8d
  404960:	lea    -0x1(%r14),%r9
  404964:	xor    %r13d,%r13d
  404967:	test   %r11d,%r11d
  40496a:	mov    %r9,0x28(%rsp)
  40496f:	mov    %r8d,0x34(%rsp)
  404974:	jle    405277 <Render_Loop+0xa07>
  40497a:	nopw   0x0(%rax,%rax,1)
  404980:	mov    0x23d919(%rip),%r11        # 6422a0 <mask_image_address>
  404987:	mov    0x23d94a(%rip),%rcx        # 6422d8 <Global>
  40498e:	mov    0x23d94b(%rip),%r12        # 6422e0 <image_address>
  404995:	mov    (%rsp),%r10
  404999:	mov    %r13,0x23f980(%rip)        # 644320 <frame>
  4049a0:	mov    %r11,0x18(%rsp)
  4049a5:	add    0x10(%rsp),%r11
  4049aa:	lea    0x200810(%rcx),%rdi
  4049b1:	lea    (%r12,%r10,1),%rbx
  4049b5:	mov    %r11,0x8(%rsp)
  4049ba:	callq  401380 <pthread_mutex_lock@plt>
  4049bf:	test   %eax,%eax
  4049c1:	jne    40562f <Render_Loop+0xdbf>
  4049c7:	mov    0x23d90a(%rip),%rdi        # 6422d8 <Global>
  4049ce:	mov    0x200868(%rdi),%rax
  4049d5:	mov    0x200870(%rdi),%rbp
  4049dc:	add    $0x1,%rax
  4049e0:	cmp    0x23fa69(%rip),%rax        # 644450 <num_nodes>
  4049e7:	mov    %rax,0x200868(%rdi)
  4049ee:	je     4052a0 <Render_Loop+0xa30>
  4049f4:	lea    0x48(%rsp),%rsi
  4049f9:	mov    $0x1,%edi
  4049fe:	callq  401160 <pthread_setcancelstate@plt>
  404a03:	jmp    404a1f <Render_Loop+0x1af>
  404a05:	nopl   (%rax)
  404a08:	lea    0x200810(%rdi),%rsi
  404a0f:	add    $0x200838,%rdi
  404a16:	callq  401130 <pthread_cond_wait@plt>
  404a1b:	test   %eax,%eax
  404a1d:	jne    404a2f <Render_Loop+0x1bf>
  404a1f:	mov    0x23d8b2(%rip),%rdi        # 6422d8 <Global>
  404a26:	cmp    %rbp,0x200870(%rdi)
  404a2d:	je     404a08 <Render_Loop+0x198>
  404a2f:	mov    0x48(%rsp),%edi
  404a33:	lea    0x4c(%rsp),%rsi
  404a38:	callq  401160 <pthread_setcancelstate@plt>
  404a3d:	mov    0x23d894(%rip),%rsi        # 6422d8 <Global>
  404a44:	lea    0x200810(%rsi),%rdi
  404a4b:	callq  401260 <pthread_mutex_unlock@plt>
  404a50:	mov    0x23f9f9(%rip),%rdi        # 644450 <num_nodes>
  404a57:	sub    $0x1,%rdi
  404a5b:	cmp    %r15,%rdi
  404a5e:	je     405300 <Render_Loop+0xa90>
  404a64:	test   %r14,%r14
  404a67:	jle    405110 <Render_Loop+0x8a0>
  404a6d:	mov    (%rsp),%r8
  404a71:	add    %r14,%r8
  404a74:	add    %r12,%r8
  404a77:	cmp    $0x6451b4,%r8
  404a7e:	setbe  %r9b
  404a82:	cmp    $0x6451b5,%rbx
  404a89:	setae  %r10b
  404a8d:	or     %r10b,%r9b
  404a90:	je     405450 <Render_Loop+0xbe0>
  404a96:	cmp    $0x16,%r14
  404a9a:	jbe    405450 <Render_Loop+0xbe0>
  404aa0:	mov    %rbx,%r11
  404aa3:	neg    %r11
  404aa6:	and    $0xf,%r11d
  404aaa:	lea    0xf(%r11),%rcx
  404aae:	cmp    0x28(%rsp),%rcx
  404ab3:	ja     405588 <Render_Loop+0xd18>
  404ab9:	test   %r11,%r11
  404abc:	je     4055ce <Render_Loop+0xd5e>
  404ac2:	movzbl 0x2406eb(%rip),%esi        # 6451b4 <background>
  404ac9:	cmp    $0x1,%r11
  404acd:	lea    0x1(%rbx),%rdx
  404ad1:	mov    %sil,(%rbx)
  404ad4:	je     405560 <Render_Loop+0xcf0>
  404ada:	movzbl 0x2406d3(%rip),%eax        # 6451b4 <background>
  404ae1:	cmp    $0x2,%r11
  404ae5:	lea    0x2(%rbx),%rdx
  404ae9:	mov    %al,0x1(%rbx)
  404aec:	je     405578 <Render_Loop+0xd08>
  404af2:	cmp    $0x3,%r11
  404af6:	lea    0x3(%rbx),%rdx
  404afa:	mov    %al,0x2(%rbx)
  404afd:	je     405590 <Render_Loop+0xd20>
  404b03:	cmp    $0x4,%r11
  404b07:	lea    0x4(%rbx),%rdx
  404b0b:	mov    %al,0x3(%rbx)
  404b0e:	je     4055b0 <Render_Loop+0xd40>
  404b14:	cmp    $0x5,%r11
  404b18:	lea    0x5(%rbx),%rdx
  404b1c:	mov    %al,0x4(%rbx)
  404b1f:	je     4055ba <Render_Loop+0xd4a>
  404b25:	cmp    $0x6,%r11
  404b29:	lea    0x6(%rbx),%rdx
  404b2d:	mov    %al,0x5(%rbx)
  404b30:	je     4055c4 <Render_Loop+0xd54>
  404b36:	cmp    $0x7,%r11
  404b3a:	lea    0x7(%rbx),%rdx
  404b3e:	mov    %al,0x6(%rbx)
  404b41:	je     4055df <Render_Loop+0xd6f>
  404b47:	cmp    $0x8,%r11
  404b4b:	lea    0x8(%rbx),%rdx
  404b4f:	mov    %al,0x7(%rbx)
  404b52:	je     4055e9 <Render_Loop+0xd79>
  404b58:	cmp    $0x9,%r11
  404b5c:	lea    0x9(%rbx),%rdx
  404b60:	mov    %al,0x8(%rbx)
  404b63:	je     4055f3 <Render_Loop+0xd83>
  404b69:	cmp    $0xa,%r11
  404b6d:	lea    0xa(%rbx),%rdx
  404b71:	mov    %al,0x9(%rbx)
  404b74:	je     4055fd <Render_Loop+0xd8d>
  404b7a:	cmp    $0xb,%r11
  404b7e:	lea    0xb(%rbx),%rdx
  404b82:	mov    %al,0xa(%rbx)
  404b85:	je     405607 <Render_Loop+0xd97>
  404b8b:	cmp    $0xc,%r11
  404b8f:	lea    0xc(%rbx),%rdx
  404b93:	mov    %al,0xb(%rbx)
  404b96:	je     405611 <Render_Loop+0xda1>
  404b9c:	cmp    $0xd,%r11
  404ba0:	lea    0xd(%rbx),%rdx
  404ba4:	mov    %al,0xc(%rbx)
  404ba7:	je     40561b <Render_Loop+0xdab>
  404bad:	cmp    $0xf,%r11
  404bb1:	lea    0xe(%rbx),%rdx
  404bb5:	mov    %al,0xd(%rbx)
  404bb8:	jne    405625 <Render_Loop+0xdb5>
  404bbe:	lea    0xf(%rbx),%rdx
  404bc2:	mov    %al,0xe(%rbx)
  404bc5:	mov    $0xf,%ebp
  404bca:	nopw   0x0(%rax,%rax,1)
  404bd0:	mov    %eax,0x18(%rsp)
  404bd4:	mov    %r14,%rdi
  404bd7:	movd   0x18(%rsp),%xmm6
  404bdd:	sub    %r11,%rdi
  404be0:	add    (%rsp),%r11
  404be4:	mov    %rdi,%rbx
  404be7:	punpcklbw %xmm6,%xmm6
  404beb:	shr    $0x4,%rbx
  404bef:	add    %r11,%r12
  404bf2:	cmp    $0x4,%rbx
  404bf6:	punpcklwd %xmm6,%xmm6
  404bfa:	pshufd $0x0,%xmm6,%xmm7
  404bff:	movdqa %xmm7,%xmm8
  404c04:	jbe    4055a0 <Render_Loop+0xd30>
  404c0a:	lea    -0x5(%rbx),%r10
  404c0e:	xor    %r9d,%r9d
  404c11:	and    $0xfffffffffffffffc,%r10
  404c15:	lea    0x4(%r10),%r8
  404c19:	shr    $0x2,%r10
  404c1d:	add    $0x1,%r10
  404c21:	and    $0x7,%r10d
  404c25:	je     404d88 <Render_Loop+0x518>
  404c2b:	cmp    $0x1,%r10
  404c2f:	je     404d56 <Render_Loop+0x4e6>
  404c35:	cmp    $0x2,%r10
  404c39:	je     404d2d <Render_Loop+0x4bd>
  404c3f:	cmp    $0x3,%r10
  404c43:	je     404d04 <Render_Loop+0x494>
  404c49:	cmp    $0x4,%r10
  404c4d:	je     404cdb <Render_Loop+0x46b>
  404c53:	cmp    $0x5,%r10
  404c57:	je     404cb2 <Render_Loop+0x442>
  404c59:	cmp    $0x6,%r10
  404c5d:	je     404c89 <Render_Loop+0x419>
  404c5f:	prefetcht0 0x280(%r12)
  404c68:	movaps %xmm7,(%r12)
  404c6d:	mov    $0x4,%r9d
  404c73:	add    $0x40,%r12
  404c77:	movaps %xmm7,-0x30(%r12)
  404c7d:	movaps %xmm7,-0x20(%r12)
  404c83:	movaps %xmm7,-0x10(%r12)
  404c89:	prefetcht0 0x280(%r12)
  404c92:	add    $0x4,%r9
  404c96:	add    $0x40,%r12
  404c9a:	movaps %xmm8,-0x40(%r12)
  404ca0:	movaps %xmm8,-0x30(%r12)
  404ca6:	movaps %xmm8,-0x20(%r12)
  404cac:	movaps %xmm8,-0x10(%r12)
  404cb2:	prefetcht0 0x280(%r12)
  404cbb:	add    $0x4,%r9
  404cbf:	add    $0x40,%r12
  404cc3:	movaps %xmm8,-0x40(%r12)
  404cc9:	movaps %xmm8,-0x30(%r12)
  404ccf:	movaps %xmm8,-0x20(%r12)
  404cd5:	movaps %xmm8,-0x10(%r12)
  404cdb:	prefetcht0 0x280(%r12)
  404ce4:	add    $0x4,%r9
  404ce8:	add    $0x40,%r12
  404cec:	movaps %xmm8,-0x40(%r12)
  404cf2:	movaps %xmm8,-0x30(%r12)
  404cf8:	movaps %xmm8,-0x20(%r12)
  404cfe:	movaps %xmm8,-0x10(%r12)
  404d04:	prefetcht0 0x280(%r12)
  404d0d:	add    $0x4,%r9
  404d11:	add    $0x40,%r12
  404d15:	movaps %xmm8,-0x40(%r12)
  404d1b:	movaps %xmm8,-0x30(%r12)
  404d21:	movaps %xmm8,-0x20(%r12)
  404d27:	movaps %xmm8,-0x10(%r12)
  404d2d:	prefetcht0 0x280(%r12)
  404d36:	add    $0x4,%r9
  404d3a:	add    $0x40,%r12
  404d3e:	movaps %xmm8,-0x40(%r12)
  404d44:	movaps %xmm8,-0x30(%r12)
  404d4a:	movaps %xmm8,-0x20(%r12)
  404d50:	movaps %xmm8,-0x10(%r12)
  404d56:	add    $0x4,%r9
  404d5a:	prefetcht0 0x280(%r12)
  404d63:	add    $0x40,%r12
  404d67:	movaps %xmm8,-0x40(%r12)
  404d6d:	movaps %xmm8,-0x30(%r12)
  404d73:	movaps %xmm8,-0x20(%r12)
  404d79:	movaps %xmm8,-0x10(%r12)
  404d7f:	cmp    %r9,%r8
  404d82:	je     404ee5 <Render_Loop+0x675>
  404d88:	add    $0x20,%r9
  404d8c:	prefetcht0 0x280(%r12)
  404d95:	prefetcht0 0x2c0(%r12)
  404d9e:	movaps %xmm8,(%r12)
  404da3:	prefetcht0 0x300(%r12)
  404dac:	prefetcht0 0x340(%r12)
  404db5:	prefetcht0 0x380(%r12)
  404dbe:	prefetcht0 0x3c0(%r12)
  404dc7:	prefetcht0 0x400(%r12)
  404dd0:	movaps %xmm8,0x10(%r12)
  404dd6:	prefetcht0 0x440(%r12)
  404ddf:	add    $0x200,%r12
  404de6:	movaps %xmm8,-0x1e0(%r12)
  404def:	movaps %xmm8,-0x1d0(%r12)
  404df8:	movaps %xmm8,-0x1c0(%r12)
  404e01:	movaps %xmm8,-0x1b0(%r12)
  404e0a:	movaps %xmm8,-0x1a0(%r12)
  404e13:	movaps %xmm8,-0x190(%r12)
  404e1c:	movaps %xmm8,-0x180(%r12)
  404e25:	movaps %xmm8,-0x170(%r12)
  404e2e:	movaps %xmm8,-0x160(%r12)
  404e37:	movaps %xmm8,-0x150(%r12)
  404e40:	movaps %xmm8,-0x140(%r12)
  404e49:	movaps %xmm8,-0x130(%r12)
  404e52:	movaps %xmm8,-0x120(%r12)
  404e5b:	movaps %xmm8,-0x110(%r12)
  404e64:	movaps %xmm8,-0x100(%r12)
  404e6d:	movaps %xmm8,-0xf0(%r12)
  404e76:	movaps %xmm8,-0xe0(%r12)
  404e7f:	movaps %xmm8,-0xd0(%r12)
  404e88:	movaps %xmm8,-0xc0(%r12)
  404e91:	movaps %xmm8,-0xb0(%r12)
  404e9a:	movaps %xmm8,-0xa0(%r12)
  404ea3:	movaps %xmm8,-0x90(%r12)
  404eac:	movaps %xmm8,-0x80(%r12)
  404eb2:	movaps %xmm8,-0x70(%r12)
  404eb8:	movaps %xmm8,-0x60(%r12)
  404ebe:	movaps %xmm8,-0x50(%r12)
  404ec4:	movaps %xmm8,-0x40(%r12)
  404eca:	movaps %xmm8,-0x30(%r12)
  404ed0:	movaps %xmm8,-0x20(%r12)
  404ed6:	movaps %xmm8,-0x10(%r12)
  404edc:	cmp    %r9,%r8
  404edf:	jne    404d88 <Render_Loop+0x518>
  404ee5:	mov    %r8,%r11
  404ee8:	lea    0x1(%r8),%rax
  404eec:	lea    0x10(%r12),%rcx
  404ef1:	not    %r11
  404ef4:	add    %rbx,%r11
  404ef7:	and    $0x7,%r11d
  404efb:	cmp    %rax,%rbx
  404efe:	movaps %xmm8,(%r12)
  404f03:	jbe    404fc2 <Render_Loop+0x752>
  404f09:	test   %r11,%r11
  404f0c:	je     404f8d <Render_Loop+0x71d>
  404f0e:	cmp    $0x1,%r11
  404f12:	je     404f7b <Render_Loop+0x70b>
  404f14:	cmp    $0x2,%r11
  404f18:	je     404f6f <Render_Loop+0x6ff>
  404f1a:	cmp    $0x3,%r11
  404f1e:	je     404f63 <Render_Loop+0x6f3>
  404f20:	cmp    $0x4,%r11
  404f24:	je     404f57 <Render_Loop+0x6e7>
  404f26:	cmp    $0x5,%r11
  404f2a:	je     404f4b <Render_Loop+0x6db>
  404f2c:	cmp    $0x6,%r11
  404f30:	je     404f3f <Render_Loop+0x6cf>
  404f32:	movaps %xmm8,(%rcx)
  404f36:	lea    0x2(%r8),%rax
  404f3a:	lea    0x20(%r12),%rcx
  404f3f:	movaps %xmm8,(%rcx)
  404f43:	add    $0x1,%rax
  404f47:	add    $0x10,%rcx
  404f4b:	movaps %xmm8,(%rcx)
  404f4f:	add    $0x1,%rax
  404f53:	add    $0x10,%rcx
  404f57:	movaps %xmm8,(%rcx)
  404f5b:	add    $0x1,%rax
  404f5f:	add    $0x10,%rcx
  404f63:	movaps %xmm8,(%rcx)
  404f67:	add    $0x1,%rax
  404f6b:	add    $0x10,%rcx
  404f6f:	movaps %xmm8,(%rcx)
  404f73:	add    $0x1,%rax
  404f77:	add    $0x10,%rcx
  404f7b:	add    $0x1,%rax
  404f7f:	add    $0x10,%rcx
  404f83:	movaps %xmm8,-0x10(%rcx)
  404f88:	cmp    %rax,%rbx
  404f8b:	jbe    404fc2 <Render_Loop+0x752>
  404f8d:	add    $0x8,%rax
  404f91:	sub    $0xffffffffffffff80,%rcx
  404f95:	movaps %xmm8,-0x80(%rcx)
  404f9a:	movaps %xmm8,-0x70(%rcx)
  404f9f:	movaps %xmm8,-0x60(%rcx)
  404fa4:	movaps %xmm8,-0x50(%rcx)
  404fa9:	movaps %xmm8,-0x40(%rcx)
  404fae:	movaps %xmm8,-0x30(%rcx)
  404fb3:	movaps %xmm8,-0x20(%rcx)
  404fb8:	movaps %xmm8,-0x10(%rcx)
  404fbd:	cmp    %rax,%rbx
  404fc0:	ja     404f8d <Render_Loop+0x71d>
  404fc2:	mov    %rdi,%r12
  404fc5:	and    $0xfffffffffffffff0,%r12
  404fc9:	add    %r12,%rbp
  404fcc:	cmp    %rdi,%r12
  404fcf:	lea    (%rdx,%r12,1),%rbx
  404fd3:	je     405110 <Render_Loop+0x8a0>
  404fd9:	mov    %rbp,%rsi
  404fdc:	movzbl 0x2401d0(%rip),%r9d        # 6451b4 <background>
  404fe4:	lea    0x1(%rbp),%r8
  404fe8:	not    %rsi
  404feb:	mov    %rbx,%r10
  404fee:	add    %r14,%rsi
  404ff1:	sub    %rbp,%r10
  404ff4:	and    $0x7,%esi
  404ff7:	cmp    %r8,%r14
  404ffa:	mov    %r9b,(%rbx)
  404ffd:	jle    405110 <Render_Loop+0x8a0>
  405003:	test   %rsi,%rsi
  405006:	je     40509f <Render_Loop+0x82f>
  40500c:	cmp    $0x1,%rsi
  405010:	je     40508b <Render_Loop+0x81b>
  405012:	cmp    $0x2,%rsi
  405016:	je     40507c <Render_Loop+0x80c>
  405018:	cmp    $0x3,%rsi
  40501c:	je     40506d <Render_Loop+0x7fd>
  40501e:	cmp    $0x4,%rsi
  405022:	je     40505e <Render_Loop+0x7ee>
  405024:	cmp    $0x5,%rsi
  405028:	je     40504e <Render_Loop+0x7de>
  40502a:	cmp    $0x6,%rsi
  40502e:	je     40503f <Render_Loop+0x7cf>
  405030:	movzbl 0x24017d(%rip),%ebx        # 6451b4 <background>
  405037:	mov    %bl,(%r10,%r8,1)
  40503b:	lea    0x2(%rbp),%r8
  40503f:	movzbl 0x24016e(%rip),%ebp        # 6451b4 <background>
  405046:	mov    %bpl,(%r10,%r8,1)
  40504a:	add    $0x1,%r8
  40504e:	movzbl 0x24015e(%rip),%r11d        # 6451b4 <background>
  405056:	mov    %r11b,(%r10,%r8,1)
  40505a:	add    $0x1,%r8
  40505e:	movzbl 0x24014f(%rip),%ecx        # 6451b4 <background>
  405065:	mov    %cl,(%r10,%r8,1)
  405069:	add    $0x1,%r8
  40506d:	movzbl 0x240140(%rip),%eax        # 6451b4 <background>
  405074:	mov    %al,(%r10,%r8,1)
  405078:	add    $0x1,%r8
  40507c:	movzbl 0x240131(%rip),%edx        # 6451b4 <background>
  405083:	mov    %dl,(%r10,%r8,1)
  405087:	add    $0x1,%r8
  40508b:	movzbl 0x240122(%rip),%edi        # 6451b4 <background>
  405092:	mov    %dil,(%r10,%r8,1)
  405096:	add    $0x1,%r8
  40509a:	cmp    %r8,%r14
  40509d:	jle    405110 <Render_Loop+0x8a0>
  40509f:	movzbl 0x24010d(%rip),%r12d        # 6451b4 <background>
  4050a7:	mov    %r12b,(%r10,%r8,1)
  4050ab:	movzbl 0x240102(%rip),%esi        # 6451b4 <background>
  4050b2:	mov    %sil,0x1(%r10,%r8,1)
  4050b7:	movzbl 0x2400f5(%rip),%r9d        # 6451b4 <background>
  4050bf:	mov    %r9b,0x2(%r10,%r8,1)
  4050c4:	movzbl 0x2400e9(%rip),%ebx        # 6451b4 <background>
  4050cb:	mov    %bl,0x3(%r10,%r8,1)
  4050d0:	movzbl 0x2400dd(%rip),%ebp        # 6451b4 <background>
  4050d7:	mov    %bpl,0x4(%r10,%r8,1)
  4050dc:	movzbl 0x2400d0(%rip),%r11d        # 6451b4 <background>
  4050e4:	mov    %r11b,0x5(%r10,%r8,1)
  4050e9:	movzbl 0x2400c4(%rip),%ecx        # 6451b4 <background>
  4050f0:	mov    %cl,0x6(%r10,%r8,1)
  4050f5:	movzbl 0x2400b8(%rip),%eax        # 6451b4 <background>
  4050fc:	mov    %al,0x7(%r10,%r8,1)
  405101:	add    $0x8,%r8
  405105:	cmp    %r8,%r14
  405108:	jg     40509f <Render_Loop+0x82f>
  40510a:	nopw   0x0(%rax,%rax,1)
  405110:	cmpw   $0x0,0x2400a4(%rip)        # 6451bc <adaptive>
  405118:	jne    4053a0 <Render_Loop+0xb30>
  40511e:	test   %r15,%r15
  405121:	je     405380 <Render_Loop+0xb10>
  405127:	mov    0x23d1aa(%rip),%rdx        # 6422d8 <Global>
  40512e:	lea    0x200810(%rdx),%rdi
  405135:	callq  401380 <pthread_mutex_lock@plt>
  40513a:	test   %eax,%eax
  40513c:	jne    40562f <Render_Loop+0xdbf>
  405142:	mov    0x23d18f(%rip),%rdi        # 6422d8 <Global>
  405149:	mov    0x200868(%rdi),%r12
  405150:	mov    0x200870(%rdi),%rbp
  405157:	add    $0x1,%r12
  40515b:	cmp    0x23f2ee(%rip),%r12        # 644450 <num_nodes>
  405162:	mov    %r12,0x200868(%rdi)
  405169:	je     4052d0 <Render_Loop+0xa60>
  40516f:	lea    0x48(%rsp),%rsi
  405174:	mov    $0x1,%edi
  405179:	callq  401160 <pthread_setcancelstate@plt>
  40517e:	jmp    405197 <Render_Loop+0x927>
  405180:	lea    0x200810(%rdi),%rsi
  405187:	add    $0x200838,%rdi
  40518e:	callq  401130 <pthread_cond_wait@plt>
  405193:	test   %eax,%eax
  405195:	jne    4051a7 <Render_Loop+0x937>
  405197:	mov    0x23d13a(%rip),%rdi        # 6422d8 <Global>
  40519e:	cmp    %rbp,0x200870(%rdi)
  4051a5:	je     405180 <Render_Loop+0x910>
  4051a7:	mov    0x48(%rsp),%edi
  4051ab:	lea    0x4c(%rsp),%rsi
  4051b0:	callq  401160 <pthread_setcancelstate@plt>
  4051b5:	mov    0x23d11c(%rip),%rdi        # 6422d8 <Global>
  4051bc:	lea    0x200810(%rdi),%rdi
  4051c3:	callq  401260 <pthread_mutex_unlock@plt>
  4051c8:	mov    0x23f281(%rip),%r10        # 644450 <num_nodes>
  4051cf:	mov    0x23d102(%rip),%r9        # 6422d8 <Global>
  4051d6:	mov    %r15,%r11
  4051d9:	shl    $0xb,%r11
  4051dd:	mov    %r15,%rdi
  4051e0:	mov    %r10,%rbx
  4051e3:	mov    %r10,0x8(%r9)
  4051e7:	shl    $0xb,%rbx
  4051eb:	add    %r9,%rbx
  4051ee:	add    %r11,%r9
  4051f1:	mov    %r10,0x10(%rbx)
  4051f5:	movq   $0x0,0x10(%r9)
  4051fd:	callq  40b040 <Render>
  405202:	test   %r15,%r15
  405205:	jne    405260 <Render_Loop+0x9f0>
  405207:	mov    0x219f97(%rip),%ecx        # 61f1a4 <ROTATE_STEPS>
  40520d:	cmp    $0x1,%ecx
  405210:	jle    4053c8 <Render_Loop+0xb58>
  405216:	imul   0x34(%rsp),%ecx
  40521b:	lea    0x50(%rsp),%rdi
  405220:	mov    $0x644340,%edx
  405225:	mov    $0x41915e,%esi
  40522a:	xor    %eax,%eax
  40522c:	lea    0x3e8(%rcx),%r10d
  405233:	movslq %r10d,%rcx
  405236:	add    %r13,%rcx
  405239:	callq  401330 <sprintf@plt>
  40523e:	mov    0x23f1db(%rip),%rsi        # 644420 <image_len>
  405245:	mov    0x23d094(%rip),%r8        # 6422e0 <image_address>
  40524c:	lea    0x50(%rsp),%rdi
  405251:	mov    0x23f1d0(%rip),%rdx        # 644428 <image_len+0x8>
  405258:	mov    %rsi,%rcx
  40525b:	callq  404510 <WriteGrayscaleTIFF>
  405260:	movslq 0x219f3d(%rip),%rbx        # 61f1a4 <ROTATE_STEPS>
  405267:	add    $0x1,%r13
  40526b:	cmp    %r13,%rbx
  40526e:	mov    %rbx,%r11
  405271:	jg     404980 <Render_Loop+0x110>
  405277:	addq   $0x1,0x20(%rsp)
  40527d:	mov    0x20(%rsp),%r13
  405282:	cmp    $0x3,%r13
  405286:	jne    40495b <Render_Loop+0xeb>
  40528c:	add    $0x128,%rsp
  405293:	pop    %rbx
  405294:	pop    %rbp
  405295:	pop    %r12
  405297:	pop    %r13
  405299:	pop    %r14
  40529b:	pop    %r15
  40529d:	retq   
  40529e:	xchg   %ax,%ax
  4052a0:	xor    %edx,%edx
  4052a2:	test   %rbp,%rbp
  4052a5:	movq   $0x0,0x200868(%rdi)
  4052b0:	sete   %dl
  4052b3:	add    $0x200838,%rdi
  4052ba:	mov    %rdx,0x38(%rdi)
  4052be:	callq  401100 <pthread_cond_broadcast@plt>
  4052c3:	jmpq   404a3d <Render_Loop+0x1cd>
  4052c8:	nopl   0x0(%rax,%rax,1)
  4052d0:	xor    %esi,%esi
  4052d2:	test   %rbp,%rbp
  4052d5:	movq   $0x0,0x200868(%rdi)
  4052e0:	sete   %sil
  4052e4:	add    $0x200838,%rdi
  4052eb:	mov    %rsi,0x38(%rdi)
  4052ef:	callq  401100 <pthread_cond_broadcast@plt>
  4052f4:	jmpq   4051b5 <Render_Loop+0x945>
  4052f9:	nopl   0x0(%rax)
  405300:	movslq 0x23cff9(%rip),%r10        # 642300 <image_length>
  405307:	mov    (%rsp),%rbp
  40530b:	cmp    %r10,%rbp
  40530e:	jge    405334 <Render_Loop+0xac4>
  405310:	mov    %rbp,%rbx
  405313:	nopl   0x0(%rax,%rax,1)
  405318:	movzbl 0x23fe94(%rip),%r11d        # 6451b4 <background>
  405320:	mov    %r11b,(%r12,%rbx,1)
  405324:	movslq 0x23cfd5(%rip),%rcx        # 642300 <image_length>
  40532b:	add    $0x1,%rbx
  40532f:	cmp    %rbx,%rcx
  405332:	jg     405318 <Render_Loop+0xaa8>
  405334:	cmpw   $0x0,0x23fe80(%rip)        # 6451bc <adaptive>
  40533c:	je     40511e <Render_Loop+0x8ae>
  405342:	mov    0x10(%rsp),%rax
  405347:	cmp    0x23cf7a(%rip),%rax        # 6422c8 <mask_image_length>
  40534e:	jge    40511e <Render_Loop+0x8ae>
  405354:	mov    0x18(%rsp),%r8
  405359:	nopl   0x0(%rax)
  405360:	movb   $0x0,(%r8,%rax,1)
  405365:	add    $0x1,%rax
  405369:	cmp    %rax,0x23cf58(%rip)        # 6422c8 <mask_image_length>
  405370:	jg     405360 <Render_Loop+0xaf0>
  405372:	test   %r15,%r15
  405375:	jne    405127 <Render_Loop+0x8b7>
  40537b:	nopl   0x0(%rax,%rax,1)
  405380:	mov    0x20(%rsp),%rdi
  405385:	movsd  0x13e53(%rip),%xmm0        # 4191e0 <__dso_handle+0x418>
  40538d:	callq  40b8b0 <Select_View>
  405392:	jmpq   405127 <Render_Loop+0x8b7>
  405397:	nopw   0x0(%rax,%rax,1)
  4053a0:	mov    0x38(%rsp),%rbx
  4053a5:	test   %rbx,%rbx
  4053a8:	jle    40511e <Render_Loop+0x8ae>
  4053ae:	mov    0x8(%rsp),%rdi
  4053b3:	mov    %rbx,%rdx
  4053b6:	xor    %esi,%esi
  4053b8:	callq  4011c0 <memset@plt>
  4053bd:	jmpq   40511e <Render_Loop+0x8ae>
  4053c2:	nopw   0x0(%rax,%rax,1)
  4053c8:	mov    $0x644340,%r8d
  4053ce:	mov    (%r8),%edx
  4053d1:	add    $0x4,%r8
  4053d5:	lea    -0x1010101(%rdx),%eax
  4053db:	not    %edx
  4053dd:	and    %edx,%eax
  4053df:	mov    %eax,%r12d
  4053e2:	and    $0x80808080,%r12d
  4053e9:	je     4053ce <Render_Loop+0xb5e>
  4053eb:	mov    %r12d,%esi
  4053ee:	lea    0x2(%r8),%rbp
  4053f2:	mov    $0x66,%r9d
  4053f8:	shr    $0x10,%esi
  4053fb:	test   $0x8080,%eax
  405400:	mov    0x23f021(%rip),%rdx        # 644428 <image_len+0x8>
  405407:	cmovne %r12d,%esi
  40540b:	cmove  %rbp,%r8
  40540f:	mov    %esi,%edi
  405411:	add    %sil,%dil
  405414:	mov    0x23f005(%rip),%rsi        # 644420 <image_len>
  40541b:	mov    $0x644340,%edi
  405420:	sbb    $0x644343,%r8
  405427:	mov    %r9w,0x644344(%r8)
  40542f:	movl   $0x6669742e,0x644340(%r8)
  40543a:	mov    0x23ce9f(%rip),%r8        # 6422e0 <image_address>
  405441:	mov    %rsi,%rcx
  405444:	callq  404510 <WriteGrayscaleTIFF>
  405449:	jmpq   405260 <Render_Loop+0x9f0>
  40544e:	xchg   %ax,%ax
  405450:	mov    %r14,%r8
  405453:	lea    (%rbx,%r14,1),%r10
  405457:	and    $0x7,%r8d
  40545b:	je     4054f9 <Render_Loop+0xc89>
  405461:	cmp    $0x1,%r8
  405465:	je     4054e0 <Render_Loop+0xc70>
  405467:	cmp    $0x2,%r8
  40546b:	je     4054d1 <Render_Loop+0xc61>
  40546d:	cmp    $0x3,%r8
  405471:	je     4054c1 <Render_Loop+0xc51>
  405473:	cmp    $0x4,%r8
  405477:	je     4054b2 <Render_Loop+0xc42>
  405479:	cmp    $0x5,%r8
  40547d:	je     4054a2 <Render_Loop+0xc32>
  40547f:	cmp    $0x6,%r8
  405483:	je     405493 <Render_Loop+0xc23>
  405485:	movzbl 0x23fd28(%rip),%edx        # 6451b4 <background>
  40548c:	add    $0x1,%rbx
  405490:	mov    %dl,-0x1(%rbx)
  405493:	movzbl 0x23fd1a(%rip),%edi        # 6451b4 <background>
  40549a:	add    $0x1,%rbx
  40549e:	mov    %dil,-0x1(%rbx)
  4054a2:	movzbl 0x23fd0a(%rip),%r12d        # 6451b4 <background>
  4054aa:	add    $0x1,%rbx
  4054ae:	mov    %r12b,-0x1(%rbx)
  4054b2:	movzbl 0x23fcfb(%rip),%esi        # 6451b4 <background>
  4054b9:	add    $0x1,%rbx
  4054bd:	mov    %sil,-0x1(%rbx)
  4054c1:	movzbl 0x23fceb(%rip),%r9d        # 6451b4 <background>
  4054c9:	add    $0x1,%rbx
  4054cd:	mov    %r9b,-0x1(%rbx)
  4054d1:	movzbl 0x23fcdc(%rip),%ebp        # 6451b4 <background>
  4054d8:	add    $0x1,%rbx
  4054dc:	mov    %bpl,-0x1(%rbx)
  4054e0:	movzbl 0x23fccc(%rip),%r11d        # 6451b4 <background>
  4054e8:	add    $0x1,%rbx
  4054ec:	cmp    %r10,%rbx
  4054ef:	mov    %r11b,-0x1(%rbx)
  4054f3:	je     405110 <Render_Loop+0x8a0>
  4054f9:	movzbl 0x23fcb4(%rip),%ecx        # 6451b4 <background>
  405500:	add    $0x8,%rbx
  405504:	mov    %cl,-0x8(%rbx)
  405507:	movzbl 0x23fca6(%rip),%eax        # 6451b4 <background>
  40550e:	mov    %al,-0x7(%rbx)
  405511:	movzbl 0x23fc9b(%rip),%r8d        # 6451b4 <background>
  405519:	mov    %r8b,-0x6(%rbx)
  40551d:	movzbl 0x23fc90(%rip),%edx        # 6451b4 <background>
  405524:	mov    %dl,-0x5(%rbx)
  405527:	movzbl 0x23fc86(%rip),%edi        # 6451b4 <background>
  40552e:	mov    %dil,-0x4(%rbx)
  405532:	movzbl 0x23fc7a(%rip),%r12d        # 6451b4 <background>
  40553a:	mov    %r12b,-0x3(%rbx)
  40553e:	movzbl 0x23fc6f(%rip),%esi        # 6451b4 <background>
  405545:	mov    %sil,-0x2(%rbx)
  405549:	movzbl 0x23fc63(%rip),%r9d        # 6451b4 <background>
  405551:	cmp    %r10,%rbx
  405554:	mov    %r9b,-0x1(%rbx)
  405558:	jne    4054f9 <Render_Loop+0xc89>
  40555a:	jmpq   405110 <Render_Loop+0x8a0>
  40555f:	nop
  405560:	mov    $0x1,%ebp
  405565:	movzbl 0x23fc48(%rip),%eax        # 6451b4 <background>
  40556c:	jmpq   404bd0 <Render_Loop+0x360>
  405571:	nopl   0x0(%rax)
  405578:	mov    $0x2,%ebp
  40557d:	jmpq   404bd0 <Render_Loop+0x360>
  405582:	nopw   0x0(%rax,%rax,1)
  405588:	xor    %ebp,%ebp
  40558a:	jmpq   404fd9 <Render_Loop+0x769>
  40558f:	nop
  405590:	mov    $0x3,%ebp
  405595:	jmpq   404bd0 <Render_Loop+0x360>
  40559a:	nopw   0x0(%rax,%rax,1)
  4055a0:	xor    %r8d,%r8d
  4055a3:	jmpq   404ee5 <Render_Loop+0x675>
  4055a8:	nopl   0x0(%rax,%rax,1)
  4055b0:	mov    $0x4,%ebp
  4055b5:	jmpq   404bd0 <Render_Loop+0x360>
  4055ba:	mov    $0x5,%ebp
  4055bf:	jmpq   404bd0 <Render_Loop+0x360>
  4055c4:	mov    $0x6,%ebp
  4055c9:	jmpq   404bd0 <Render_Loop+0x360>
  4055ce:	mov    %rbx,%rdx
  4055d1:	xor    %ebp,%ebp
  4055d3:	movzbl 0x23fbda(%rip),%eax        # 6451b4 <background>
  4055da:	jmpq   404bd0 <Render_Loop+0x360>
  4055df:	mov    $0x7,%ebp
  4055e4:	jmpq   404bd0 <Render_Loop+0x360>
  4055e9:	mov    $0x8,%ebp
  4055ee:	jmpq   404bd0 <Render_Loop+0x360>
  4055f3:	mov    $0x9,%ebp
  4055f8:	jmpq   404bd0 <Render_Loop+0x360>
  4055fd:	mov    $0xa,%ebp
  405602:	jmpq   404bd0 <Render_Loop+0x360>
  405607:	mov    $0xb,%ebp
  40560c:	jmpq   404bd0 <Render_Loop+0x360>
  405611:	mov    $0xc,%ebp
  405616:	jmpq   404bd0 <Render_Loop+0x360>
  40561b:	mov    $0xd,%ebp
  405620:	jmpq   404bd0 <Render_Loop+0x360>
  405625:	mov    $0xe,%ebp
  40562a:	jmpq   404bd0 <Render_Loop+0x360>
  40562f:	mov    $0x418dd0,%edi
  405634:	callq  401110 <puts@plt>
  405639:	mov    $0xffffffff,%edi
  40563e:	callq  401340 <exit@plt>
  405643:	nopl   (%rax)
  405646:	nopw   %cs:0x0(%rax,%rax,1)

0000000000405650 <Frame>:
  405650:	push   %rbp
  405651:	push   %rbx
  405652:	sub    $0x18,%rsp
  405656:	callq  408f80 <Init_Options>
  40565b:	mov    0x23edee(%rip),%rsi        # 644450 <num_nodes>
  405662:	mov    $0x418f48,%edi
  405667:	xor    %eax,%eax
  405669:	callq  401170 <printf@plt>
  40566e:	mov    0x23cb0b(%rip),%rdi        # 642180 <stdout@@GLIBC_2.2.5>
  405675:	callq  401280 <fflush@plt>
  40567a:	callq  403ba0 <Init_Decomposition>
  40567f:	mov    0x23edca(%rip),%rsi        # 644450 <num_nodes>
  405686:	mov    $0x418f80,%edi
  40568b:	xor    %eax,%eax
  40568d:	callq  401170 <printf@plt>
  405692:	mov    0x23cae7(%rip),%rdi        # 642180 <stdout@@GLIBC_2.2.5>
  405699:	callq  401280 <fflush@plt>
  40569e:	mov    $0x20a958,%edi
  4056a3:	callq  401270 <malloc@plt>
  4056a8:	lea    0x200810(%rax),%rdi
  4056af:	xor    %esi,%esi
  4056b1:	mov    %rax,0x23cc20(%rip)        # 6422d8 <Global>
  4056b8:	callq  401370 <pthread_mutex_init@plt>
  4056bd:	test   %eax,%eax
  4056bf:	jne    4060e2 <Frame+0xa92>
  4056c5:	mov    0x23cc0c(%rip),%rax        # 6422d8 <Global>
  4056cc:	xor    %esi,%esi
  4056ce:	lea    0x200838(%rax),%rdi
  4056d5:	callq  401250 <pthread_cond_init@plt>
  4056da:	test   %eax,%eax
  4056dc:	jne    406123 <Frame+0xad3>
  4056e2:	mov    0x23cbef(%rip),%rdx        # 6422d8 <Global>
  4056e9:	xor    %esi,%esi
  4056eb:	lea    0x200878(%rdx),%rdi
  4056f2:	movq   $0x0,0x200868(%rdx)
  4056fd:	movq   $0x0,0x200870(%rdx)
  405708:	callq  401370 <pthread_mutex_init@plt>
  40570d:	test   %eax,%eax
  40570f:	jne    4060e2 <Frame+0xa92>
  405715:	mov    0x23cbbc(%rip),%rcx        # 6422d8 <Global>
  40571c:	xor    %esi,%esi
  40571e:	lea    0x2008a0(%rcx),%rdi
  405725:	callq  401250 <pthread_cond_init@plt>
  40572a:	test   %eax,%eax
  40572c:	jne    4060fe <Frame+0xaae>
  405732:	mov    0x23cb9f(%rip),%rbx        # 6422d8 <Global>
  405739:	xor    %esi,%esi
  40573b:	lea    0x2008e0(%rbx),%rdi
  405742:	movq   $0x0,0x2008d0(%rbx)
  40574d:	movq   $0x0,0x2008d8(%rbx)
  405758:	callq  401370 <pthread_mutex_init@plt>
  40575d:	mov    0x23cb74(%rip),%rsi        # 6422d8 <Global>
  405764:	lea    0x200908(%rsi),%rdi
  40576b:	xor    %esi,%esi
  40576d:	callq  401370 <pthread_mutex_init@plt>
  405772:	mov    0x23cb5f(%rip),%rdi        # 6422d8 <Global>
  405779:	xor    %esi,%esi
  40577b:	lea    0x200930(%rdi),%rdi
  405782:	callq  401370 <pthread_mutex_init@plt>
  405787:	test   %eax,%eax
  405789:	jne    40609a <Frame+0xa4a>
  40578f:	mov    $0x200958,%ebp
  405794:	nopl   0x0(%rax)
  405798:	mov    0x23cb39(%rip),%rdi        # 6422d8 <Global>
  40579f:	xor    %esi,%esi
  4057a1:	add    %rbp,%rdi
  4057a4:	callq  401370 <pthread_mutex_init@plt>
  4057a9:	test   %eax,%eax
  4057ab:	jne    40609a <Frame+0xa4a>
  4057b1:	mov    0x23cb20(%rip),%r8        # 6422d8 <Global>
  4057b8:	xor    %esi,%esi
  4057ba:	lea    0x28(%r8,%rbp,1),%rdi
  4057bf:	callq  401370 <pthread_mutex_init@plt>
  4057c4:	test   %eax,%eax
  4057c6:	jne    40609a <Frame+0xa4a>
  4057cc:	mov    0x23cb05(%rip),%r9        # 6422d8 <Global>
  4057d3:	xor    %esi,%esi
  4057d5:	lea    0x50(%r9,%rbp,1),%rdi
  4057da:	callq  401370 <pthread_mutex_init@plt>
  4057df:	test   %eax,%eax
  4057e1:	jne    40609a <Frame+0xa4a>
  4057e7:	mov    0x23caea(%rip),%r10        # 6422d8 <Global>
  4057ee:	xor    %esi,%esi
  4057f0:	lea    0x78(%r10,%rbp,1),%rdi
  4057f5:	callq  401370 <pthread_mutex_init@plt>
  4057fa:	test   %eax,%eax
  4057fc:	jne    40609a <Frame+0xa4a>
  405802:	mov    0x23cacf(%rip),%r11        # 6422d8 <Global>
  405809:	xor    %esi,%esi
  40580b:	lea    0xa0(%r11,%rbp,1),%rdi
  405813:	callq  401370 <pthread_mutex_init@plt>
  405818:	test   %eax,%eax
  40581a:	jne    40609a <Frame+0xa4a>
  405820:	mov    0x23cab1(%rip),%rax        # 6422d8 <Global>
  405827:	xor    %esi,%esi
  405829:	lea    0xc8(%rax,%rbp,1),%rdi
  405831:	callq  401370 <pthread_mutex_init@plt>
  405836:	test   %eax,%eax
  405838:	jne    40609a <Frame+0xa4a>
  40583e:	mov    0x23ca93(%rip),%rdx        # 6422d8 <Global>
  405845:	xor    %esi,%esi
  405847:	lea    0xf0(%rdx,%rbp,1),%rdi
  40584f:	callq  401370 <pthread_mutex_init@plt>
  405854:	test   %eax,%eax
  405856:	jne    40609a <Frame+0xa4a>
  40585c:	mov    0x23ca75(%rip),%rcx        # 6422d8 <Global>
  405863:	xor    %esi,%esi
  405865:	lea    0x118(%rcx,%rbp,1),%rdi
  40586d:	callq  401370 <pthread_mutex_init@plt>
  405872:	test   %eax,%eax
  405874:	jne    40609a <Frame+0xa4a>
  40587a:	add    $0x140,%rbp
  405881:	cmp    $0x20a958,%rbp
  405888:	jne    405798 <Frame+0x148>
  40588e:	xor    %esi,%esi
  405890:	mov    %rsp,%rdi
  405893:	callq  4011a0 <gettimeofday@plt>
  405898:	imul   $0xf4240,(%rsp),%rbx
  4058a0:	mov    $0x644340,%edi
  4058a5:	add    0x8(%rsp),%rbx
  4058aa:	callq  406150 <Load_Map>
  4058af:	xor    %esi,%esi
  4058b1:	mov    %rsp,%rdi
  4058b4:	callq  4011a0 <gettimeofday@plt>
  4058b9:	imul   $0xf4240,(%rsp),%rax
  4058c1:	add    0x8(%rsp),%rax
  4058c6:	cmp    %rax,%rbx
  4058c9:	jg     405db8 <Frame+0x768>
  4058cf:	sub    %rbx,%rax
  4058d2:	movabs $0x20c49ba5e353f7cf,%rsi
  4058dc:	shr    $0x3,%rax
  4058e0:	mul    %rsi
  4058e3:	shr    $0x4,%rdx
  4058e7:	mov    %rdx,%rsi
  4058ea:	mov    $0x419010,%edi
  4058ef:	xor    %eax,%eax
  4058f1:	callq  401170 <printf@plt>
  4058f6:	xor    %esi,%esi
  4058f8:	mov    %rsp,%rdi
  4058fb:	callq  4011a0 <gettimeofday@plt>
  405900:	imul   $0xf4240,(%rsp),%rbp
  405908:	add    0x8(%rsp),%rbp
  40590d:	callq  4068d0 <Compute_Normal>
  405912:	xor    %esi,%esi
  405914:	mov    %rsp,%rdi
  405917:	callq  4011a0 <gettimeofday@plt>
  40591c:	imul   $0xf4240,(%rsp),%rax
  405924:	add    0x8(%rsp),%rax
  405929:	cmp    %rax,%rbp
  40592c:	jle    405e20 <Frame+0x7d0>
  405932:	lea    -0x1(%rax),%rax
  405936:	movabs $0x20c49ba5e353f7cf,%r9
  405940:	sub    %rbp,%rax
  405943:	shr    $0x3,%rax
  405947:	mul    %r9
  40594a:	shr    $0x4,%rdx
  40594e:	mov    %rdx,%rsi
  405951:	mov    $0x419040,%edi
  405956:	xor    %eax,%eax
  405958:	callq  401170 <printf@plt>
  40595d:	xor    %esi,%esi
  40595f:	mov    %rsp,%rdi
  405962:	callq  4011a0 <gettimeofday@plt>
  405967:	imul   $0xf4240,(%rsp),%rbx
  40596f:	add    0x8(%rsp),%rbx
  405974:	callq  4086e0 <Compute_Opacity>
  405979:	xor    %esi,%esi
  40597b:	mov    %rsp,%rdi
  40597e:	callq  4011a0 <gettimeofday@plt>
  405983:	imul   $0xf4240,(%rsp),%rax
  40598b:	add    0x8(%rsp),%rax
  405990:	cmp    %rax,%rbx
  405993:	jle    405e00 <Frame+0x7b0>
  405999:	lea    -0x1(%rax),%rax
  40599d:	movabs $0x20c49ba5e353f7cf,%r11
  4059a7:	sub    %rbx,%rax
  4059aa:	shr    $0x3,%rax
  4059ae:	mul    %r11
  4059b1:	shr    $0x4,%rdx
  4059b5:	mov    %rdx,%rsi
  4059b8:	mov    $0x419078,%edi
  4059bd:	xor    %eax,%eax
  4059bf:	callq  401170 <printf@plt>
  4059c4:	callq  40b170 <Compute_Pre_View>
  4059c9:	mov    $0x1f02,%esi
  4059ce:	mov    $0x418ee8,%edi
  4059d3:	xor    %eax,%eax
  4059d5:	movq   $0x1f02,0x23ea38(%rip)        # 644418 <shd_length>
  4059e0:	callq  401170 <printf@plt>
  4059e5:	mov    $0x1f02,%edi
  4059ea:	callq  401270 <malloc@plt>
  4059ef:	test   %rax,%rax
  4059f2:	mov    %rax,0x23c8d7(%rip)        # 6422d0 <shd_address>
  4059f9:	je     4060f4 <Frame+0xaa4>
  4059ff:	movb   $0x0,(%rax)
  405a02:	mov    $0x1,%ecx
  405a07:	jmp    405a71 <Frame+0x421>
  405a09:	nopl   0x0(%rax)
  405a10:	mov    0x23c8b9(%rip),%rbp        # 6422d0 <shd_address>
  405a17:	movb   $0x0,0x1(%rbp,%rcx,1)
  405a1c:	mov    0x23c8ad(%rip),%r8        # 6422d0 <shd_address>
  405a23:	movb   $0x0,0x2(%r8,%rcx,1)
  405a29:	mov    0x23c8a0(%rip),%rsi        # 6422d0 <shd_address>
  405a30:	movb   $0x0,0x3(%rsi,%rcx,1)
  405a35:	mov    0x23c894(%rip),%r10        # 6422d0 <shd_address>
  405a3c:	movb   $0x0,0x4(%r10,%rcx,1)
  405a42:	mov    0x23c887(%rip),%rbx        # 6422d0 <shd_address>
  405a49:	movb   $0x0,0x5(%rbx,%rcx,1)
  405a4e:	mov    0x23c87b(%rip),%rdi        # 6422d0 <shd_address>
  405a55:	movb   $0x0,0x6(%rdi,%rcx,1)
  405a5a:	mov    0x23c86f(%rip),%rax        # 6422d0 <shd_address>
  405a61:	movb   $0x0,0x7(%rax,%rcx,1)
  405a66:	mov    0x23c863(%rip),%rax        # 6422d0 <shd_address>
  405a6d:	add    $0x8,%rcx
  405a71:	cmp    $0x1f01,%rcx
  405a78:	movb   $0x0,(%rax,%rcx,1)
  405a7c:	jne    405a10 <Frame+0x3c0>
  405a7e:	mov    0x2438f4(%rip),%esi        # 649378 <frust_len>
  405a84:	movq   0x2438ec(%rip),%xmm0        # 649378 <frust_len>
  405a8c:	punpcklqdq %xmm0,%xmm0
  405a90:	mov    $0x418e98,%edi
  405a95:	xor    %eax,%eax
  405a97:	imul   %esi,%esi
  405a9a:	movaps %xmm0,0x23e97f(%rip)        # 644420 <image_len>
  405aa1:	movslq %esi,%rbp
  405aa4:	mov    %esi,0x23c856(%rip)        # 642300 <image_length>
  405aaa:	mov    %rbp,%rsi
  405aad:	callq  401170 <printf@plt>
  405ab2:	mov    %rbp,%rdi
  405ab5:	callq  401270 <malloc@plt>
  405aba:	test   %rax,%rax
  405abd:	mov    %rax,0x23c81c(%rip)        # 6422e0 <image_address>
  405ac4:	je     4060ae <Frame+0xa5e>
  405aca:	xor    %r8d,%r8d
  405acd:	test   %rbp,%rbp
  405ad0:	jle    405bf8 <Frame+0x5a8>
  405ad6:	lea    -0x1(%rbp),%rdi
  405ada:	and    $0x7,%edi
  405add:	je     405be3 <Frame+0x593>
  405ae3:	cmp    $0x1,%rdi
  405ae7:	movb   $0x0,(%rax)
  405aea:	mov    $0x1,%r8d
  405af0:	mov    0x23c7e9(%rip),%rax        # 6422e0 <image_address>
  405af7:	je     405be3 <Frame+0x593>
  405afd:	cmp    $0x2,%rdi
  405b01:	je     405b5f <Frame+0x50f>
  405b03:	cmp    $0x3,%rdi
  405b07:	je     405b4f <Frame+0x4ff>
  405b09:	cmp    $0x4,%rdi
  405b0d:	je     405b3f <Frame+0x4ef>
  405b0f:	cmp    $0x5,%rdi
  405b13:	je     405b2f <Frame+0x4df>
  405b15:	cmp    $0x6,%rdi
  405b19:	jne    406070 <Frame+0xa20>
  405b1f:	movb   $0x0,(%rax,%r8,1)
  405b24:	mov    0x23c7b5(%rip),%rax        # 6422e0 <image_address>
  405b2b:	add    $0x1,%r8
  405b2f:	movb   $0x0,(%rax,%r8,1)
  405b34:	mov    0x23c7a5(%rip),%rax        # 6422e0 <image_address>
  405b3b:	add    $0x1,%r8
  405b3f:	movb   $0x0,(%rax,%r8,1)
  405b44:	mov    0x23c795(%rip),%rax        # 6422e0 <image_address>
  405b4b:	add    $0x1,%r8
  405b4f:	movb   $0x0,(%rax,%r8,1)
  405b54:	mov    0x23c785(%rip),%rax        # 6422e0 <image_address>
  405b5b:	add    $0x1,%r8
  405b5f:	movb   $0x0,(%rax,%r8,1)
  405b64:	add    $0x1,%r8
  405b68:	mov    0x23c771(%rip),%rax        # 6422e0 <image_address>
  405b6f:	lea    0x1(%r8),%r9
  405b73:	cmp    %r9,%rbp
  405b76:	movb   $0x0,(%rax,%r8,1)
  405b7b:	je     405bf8 <Frame+0x5a8>
  405b7d:	mov    0x23c75c(%rip),%r10        # 6422e0 <image_address>
  405b84:	movb   $0x0,0x1(%r10,%r8,1)
  405b8a:	mov    0x23c74f(%rip),%rbx        # 6422e0 <image_address>
  405b91:	movb   $0x0,0x2(%rbx,%r8,1)
  405b97:	mov    0x23c742(%rip),%rdi        # 6422e0 <image_address>
  405b9e:	movb   $0x0,0x3(%rdi,%r8,1)
  405ba4:	mov    0x23c735(%rip),%rax        # 6422e0 <image_address>
  405bab:	movb   $0x0,0x4(%rax,%r8,1)
  405bb1:	mov    0x23c728(%rip),%rdx        # 6422e0 <image_address>
  405bb8:	movb   $0x0,0x5(%rdx,%r8,1)
  405bbe:	mov    0x23c71b(%rip),%r9        # 6422e0 <image_address>
  405bc5:	movb   $0x0,0x6(%r9,%r8,1)
  405bcb:	mov    0x23c70e(%rip),%r11        # 6422e0 <image_address>
  405bd2:	movb   $0x0,0x7(%r11,%r8,1)
  405bd8:	mov    0x23c701(%rip),%rax        # 6422e0 <image_address>
  405bdf:	add    $0x8,%r8
  405be3:	lea    0x1(%r8),%r9
  405be7:	movb   $0x0,(%rax,%r8,1)
  405bec:	cmp    %r9,%rbp
  405bef:	jne    405b7d <Frame+0x52d>
  405bf1:	nopl   0x0(%rax)
  405bf8:	cmpq   $0x1,0x23e850(%rip)        # 644450 <num_nodes>
  405c00:	mov    0x23e819(%rip),%r10        # 644420 <image_len>
  405c07:	mov    0x23e81a(%rip),%r11        # 644428 <image_len+0x8>
  405c0e:	je     405e40 <Frame+0x7f0>
  405c14:	mov    0x23f5c5(%rip),%rbx        # 6451e0 <block_xlen>
  405c1b:	pxor   %xmm2,%xmm2
  405c1f:	pxor   %xmm1,%xmm1
  405c23:	pxor   %xmm3,%xmm3
  405c27:	cvtsi2ss %r10,%xmm2
  405c2c:	cvtsi2ss %rbx,%xmm1
  405c31:	divss  %xmm1,%xmm2
  405c35:	cvttss2si %xmm2,%rdx
  405c3a:	cvtsi2ss %rdx,%xmm3
  405c3f:	ucomiss %xmm3,%xmm2
  405c42:	jp     405c46 <Frame+0x5f6>
  405c44:	je     405c4a <Frame+0x5fa>
  405c46:	add    $0x1,%rdx
  405c4a:	mov    0x23f54f(%rip),%rcx        # 6451a0 <block_ylen>
  405c51:	pxor   %xmm4,%xmm4
  405c55:	pxor   %xmm5,%xmm5
  405c59:	mov    %rdx,0x23c650(%rip)        # 6422b0 <num_xblocks>
  405c60:	pxor   %xmm6,%xmm6
  405c64:	cvtsi2ss %r11,%xmm4
  405c69:	cvtsi2ss %rcx,%xmm5
  405c6e:	divss  %xmm5,%xmm4
  405c72:	cvttss2si %xmm4,%rax
  405c77:	cvtsi2ss %rax,%xmm6
  405c7c:	ucomiss %xmm6,%xmm4
  405c7f:	jp     405c83 <Frame+0x633>
  405c81:	je     405c87 <Frame+0x637>
  405c83:	add    $0x1,%rax
  405c87:	imul   %rcx,%rbx
  405c8b:	mov    %rax,0x23c62e(%rip)        # 6422c0 <num_yblocks>
  405c92:	mov    $0x418e98,%edi
  405c97:	imul   %rax,%rdx
  405c9b:	xor    %eax,%eax
  405c9d:	mov    %rbx,%rsi
  405ca0:	mov    %rdx,0x23e7a1(%rip)        # 644448 <num_blocks>
  405ca7:	callq  401170 <printf@plt>
  405cac:	mov    $0x1,%esi
  405cb1:	mov    %rbx,%rdi
  405cb4:	callq  401210 <calloc@plt>
  405cb9:	test   %rax,%rax
  405cbc:	mov    %rax,0x23e74d(%rip)        # 644410 <image_block>
  405cc3:	je     40605f <Frame+0xa0f>
  405cc9:	xor    %esi,%esi
  405ccb:	mov    %rsp,%rdi
  405cce:	callq  4011a0 <gettimeofday@plt>
  405cd3:	imul   $0xf4240,(%rsp),%rbp
  405cdb:	add    0x8(%rsp),%rbp
  405ce0:	callq  4076a0 <Compute_Octree>
  405ce5:	xor    %esi,%esi
  405ce7:	mov    %rsp,%rdi
  405cea:	callq  4011a0 <gettimeofday@plt>
  405cef:	imul   $0xf4240,(%rsp),%rax
  405cf7:	add    0x8(%rsp),%rax
  405cfc:	cmp    %rax,%rbp
  405cff:	jle    405de0 <Frame+0x790>
  405d05:	lea    -0x1(%rax),%rax
  405d09:	movabs $0x20c49ba5e353f7cf,%r8
  405d13:	sub    %rbp,%rax
  405d16:	shr    $0x3,%rax
  405d1a:	mul    %r8
  405d1d:	shr    $0x4,%rdx
  405d21:	mov    %rdx,%rsi
  405d24:	xor    %eax,%eax
  405d26:	mov    $0x4190b0,%edi
  405d2b:	callq  401170 <printf@plt>
  405d30:	cmpw   $0x0,0x23f484(%rip)        # 6451bc <adaptive>
  405d38:	jne    405e88 <Frame+0x838>
  405d3e:	mov    $0x644480,%edi
  405d43:	callq  406540 <Deallocate_Map>
  405d48:	mov    0x23c589(%rip),%rsi        # 6422d8 <Global>
  405d4f:	mov    $0x41916b,%edi
  405d54:	movq   $0x0,(%rsi)
  405d5b:	callq  401110 <puts@plt>
  405d60:	cmpq   $0x1,0x23e6e8(%rip)        # 644450 <num_nodes>
  405d68:	jle    405da9 <Frame+0x759>
  405d6a:	mov    $0x642320,%ebp
  405d6f:	xor    %ebx,%ebx
  405d71:	nopl   0x0(%rax)
  405d78:	xor    %ecx,%ecx
  405d7a:	xor    %esi,%esi
  405d7c:	mov    $0x404870,%edx
  405d81:	mov    %rbp,%rdi
  405d84:	callq  4010d0 <pthread_create@plt>
  405d89:	test   %eax,%eax
  405d8b:	jne    4060d0 <Frame+0xa80>
  405d91:	mov    0x23e6b8(%rip),%rdi        # 644450 <num_nodes>
  405d98:	add    $0x1,%rbx
  405d9c:	add    $0x8,%rbp
  405da0:	sub    $0x1,%rdi
  405da4:	cmp    %rbx,%rdi
  405da7:	jg     405d78 <Frame+0x728>
  405da9:	callq  404870 <Render_Loop>
  405dae:	add    $0x18,%rsp
  405db2:	pop    %rbx
  405db3:	pop    %rbp
  405db4:	retq   
  405db5:	nopl   (%rax)
  405db8:	lea    -0x1(%rax),%rax
  405dbc:	movabs $0x20c49ba5e353f7cf,%rdi
  405dc6:	sub    %rbx,%rax
  405dc9:	shr    $0x3,%rax
  405dcd:	mul    %rdi
  405dd0:	shr    $0x4,%rdx
  405dd4:	mov    %rdx,%rsi
  405dd7:	jmpq   4058ea <Frame+0x29a>
  405ddc:	nopl   0x0(%rax)
  405de0:	sub    %rbp,%rax
  405de3:	movabs $0x20c49ba5e353f7cf,%rdi
  405ded:	shr    $0x3,%rax
  405df1:	mul    %rdi
  405df4:	shr    $0x4,%rdx
  405df8:	mov    %rdx,%rsi
  405dfb:	jmpq   405d24 <Frame+0x6d4>
  405e00:	sub    %rbx,%rax
  405e03:	movabs $0x20c49ba5e353f7cf,%r10
  405e0d:	shr    $0x3,%rax
  405e11:	mul    %r10
  405e14:	shr    $0x4,%rdx
  405e18:	mov    %rdx,%rsi
  405e1b:	jmpq   4059b8 <Frame+0x368>
  405e20:	sub    %rbp,%rax
  405e23:	movabs $0x20c49ba5e353f7cf,%r8
  405e2d:	shr    $0x3,%rax
  405e31:	mul    %r8
  405e34:	shr    $0x4,%rdx
  405e38:	mov    %rdx,%rsi
  405e3b:	jmpq   405951 <Frame+0x301>
  405e40:	mov    0x23c499(%rip),%rsi        # 6422e0 <image_address>
  405e47:	mov    %r10,0x23f392(%rip)        # 6451e0 <block_xlen>
  405e4e:	mov    %r11,0x23f34b(%rip)        # 6451a0 <block_ylen>
  405e55:	movq   $0x1,0x23e5e8(%rip)        # 644448 <num_blocks>
  405e60:	movq   $0x1,0x23c445(%rip)        # 6422b0 <num_xblocks>
  405e6b:	movq   $0x1,0x23c44a(%rip)        # 6422c0 <num_yblocks>
  405e76:	mov    %rsi,0x23e593(%rip)        # 644410 <image_block>
  405e7d:	jmpq   405cc9 <Frame+0x679>
  405e82:	nopw   0x0(%rax,%rax,1)
  405e88:	mov    $0x419165,%edi
  405e8d:	callq  401110 <puts@plt>
  405e92:	movslq 0x23c467(%rip),%rbx        # 642300 <image_length>
  405e99:	mov    $0x418e98,%edi
  405e9e:	xor    %eax,%eax
  405ea0:	movdqa 0x23e578(%rip),%xmm7        # 644420 <image_len>
  405ea8:	movaps %xmm7,0x23c441(%rip)        # 6422f0 <mask_image_len>
  405eaf:	mov    %rbx,%rsi
  405eb2:	mov    %rbx,0x23c40f(%rip)        # 6422c8 <mask_image_length>
  405eb9:	callq  401170 <printf@plt>
  405ebe:	mov    %rbx,%rdi
  405ec1:	callq  401270 <malloc@plt>
  405ec6:	test   %rax,%rax
  405ec9:	mov    %rax,0x23c3d0(%rip)        # 6422a0 <mask_image_address>
  405ed0:	je     40605f <Frame+0xa0f>
  405ed6:	test   %rbx,%rbx
  405ed9:	jle    405ffe <Frame+0x9ae>
  405edf:	lea    -0x1(%rbx),%r9
  405ee3:	xor    %r10d,%r10d
  405ee6:	and    $0x7,%r9d
  405eea:	je     405ff0 <Frame+0x9a0>
  405ef0:	cmp    $0x1,%r9
  405ef4:	movb   $0x0,(%rax)
  405ef7:	mov    $0x1,%r10d
  405efd:	mov    0x23c39c(%rip),%rax        # 6422a0 <mask_image_address>
  405f04:	je     405ff0 <Frame+0x9a0>
  405f0a:	cmp    $0x2,%r9
  405f0e:	je     405f6c <Frame+0x91c>
  405f10:	cmp    $0x3,%r9
  405f14:	je     405f5c <Frame+0x90c>
  405f16:	cmp    $0x4,%r9
  405f1a:	je     405f4c <Frame+0x8fc>
  405f1c:	cmp    $0x5,%r9
  405f20:	je     405f3c <Frame+0x8ec>
  405f22:	cmp    $0x6,%r9
  405f26:	jne    406085 <Frame+0xa35>
  405f2c:	movb   $0x0,(%rax,%r10,1)
  405f31:	mov    0x23c368(%rip),%rax        # 6422a0 <mask_image_address>
  405f38:	add    $0x1,%r10
  405f3c:	movb   $0x0,(%rax,%r10,1)
  405f41:	mov    0x23c358(%rip),%rax        # 6422a0 <mask_image_address>
  405f48:	add    $0x1,%r10
  405f4c:	movb   $0x0,(%rax,%r10,1)
  405f51:	mov    0x23c348(%rip),%rax        # 6422a0 <mask_image_address>
  405f58:	add    $0x1,%r10
  405f5c:	movb   $0x0,(%rax,%r10,1)
  405f61:	mov    0x23c338(%rip),%rax        # 6422a0 <mask_image_address>
  405f68:	add    $0x1,%r10
  405f6c:	movb   $0x0,(%rax,%r10,1)
  405f71:	add    $0x1,%r10
  405f75:	mov    0x23c324(%rip),%rax        # 6422a0 <mask_image_address>
  405f7c:	lea    0x1(%r10),%r11
  405f80:	cmp    %r11,%rbx
  405f83:	movb   $0x0,(%rax,%r10,1)
  405f88:	je     405ffe <Frame+0x9ae>
  405f8a:	mov    0x23c30f(%rip),%r8        # 6422a0 <mask_image_address>
  405f91:	movb   $0x0,0x1(%r8,%r10,1)
  405f97:	mov    0x23c302(%rip),%rax        # 6422a0 <mask_image_address>
  405f9e:	movb   $0x0,0x2(%rax,%r10,1)
  405fa4:	mov    0x23c2f5(%rip),%rdx        # 6422a0 <mask_image_address>
  405fab:	movb   $0x0,0x3(%rdx,%r10,1)
  405fb1:	mov    0x23c2e8(%rip),%r9        # 6422a0 <mask_image_address>
  405fb8:	movb   $0x0,0x4(%r9,%r10,1)
  405fbe:	mov    0x23c2db(%rip),%r11        # 6422a0 <mask_image_address>
  405fc5:	movb   $0x0,0x5(%r11,%r10,1)
  405fcb:	mov    0x23c2ce(%rip),%rcx        # 6422a0 <mask_image_address>
  405fd2:	movb   $0x0,0x6(%rcx,%r10,1)
  405fd8:	mov    0x23c2c1(%rip),%rsi        # 6422a0 <mask_image_address>
  405fdf:	movb   $0x0,0x7(%rsi,%r10,1)
  405fe5:	mov    0x23c2b4(%rip),%rax        # 6422a0 <mask_image_address>
  405fec:	add    $0x8,%r10
  405ff0:	lea    0x1(%r10),%r11
  405ff4:	movb   $0x0,(%rax,%r10,1)
  405ff9:	cmp    %r11,%rbx
  405ffc:	jne    405f8a <Frame+0x93a>
  405ffe:	cmpq   $0x1,0x23e44a(%rip)        # 644450 <num_nodes>
  406006:	jne    406028 <Frame+0x9d8>
  406008:	mov    0x23c291(%rip),%rcx        # 6422a0 <mask_image_address>
  40600f:	mov    %rcx,0x23c292(%rip)        # 6422a8 <mask_image_block>
  406016:	mov    $0x419168,%edi
  40601b:	callq  401110 <puts@plt>
  406020:	jmpq   405d3e <Frame+0x6ee>
  406025:	nopl   (%rax)
  406028:	mov    0x23f1b1(%rip),%rbp        # 6451e0 <block_xlen>
  40602f:	mov    $0x418e98,%edi
  406034:	xor    %eax,%eax
  406036:	imul   0x23f162(%rip),%rbp        # 6451a0 <block_ylen>
  40603e:	mov    %rbp,%rsi
  406041:	callq  401170 <printf@plt>
  406046:	mov    $0x1,%esi
  40604b:	mov    %rbp,%rdi
  40604e:	callq  401210 <calloc@plt>
  406053:	test   %rax,%rax
  406056:	mov    %rax,0x23c24b(%rip)        # 6422a8 <mask_image_block>
  40605d:	jne    406016 <Frame+0x9c6>
  40605f:	mov    $0x418ec0,%edi
  406064:	xor    %eax,%eax
  406066:	callq  403650 <Error>
  40606b:	nopl   0x0(%rax,%rax,1)
  406070:	movb   $0x0,(%rax,%r8,1)
  406075:	add    $0x1,%r8
  406079:	mov    0x23c260(%rip),%rax        # 6422e0 <image_address>
  406080:	jmpq   405b1f <Frame+0x4cf>
  406085:	movb   $0x0,(%rax,%r10,1)
  40608a:	add    $0x1,%r10
  40608e:	mov    0x23c20b(%rip),%rax        # 6422a0 <mask_image_address>
  406095:	jmpq   405f2c <Frame+0x8dc>
  40609a:	mov    $0x418fe0,%edi
  40609f:	callq  401110 <puts@plt>
  4060a4:	mov    $0xffffffff,%edi
  4060a9:	callq  401340 <exit@plt>
  4060ae:	sub    $0x8,%rsp
  4060b2:	xor    %r9d,%r9d
  4060b5:	xor    %r8d,%r8d
  4060b8:	pushq  $0x0
  4060ba:	pushq  $0x0
  4060bc:	xor    %ecx,%ecx
  4060be:	pushq  $0x0
  4060c0:	xor    %edx,%edx
  4060c2:	xor    %esi,%esi
  4060c4:	mov    $0x418ec0,%edi
  4060c9:	xor    %eax,%eax
  4060cb:	callq  403650 <Error>
  4060d0:	mov    $0x419179,%edi
  4060d5:	callq  401110 <puts@plt>
  4060da:	or     $0xffffffff,%edi
  4060dd:	callq  401340 <exit@plt>
  4060e2:	mov    $0x418fb8,%edi
  4060e7:	callq  401110 <puts@plt>
  4060ec:	or     $0xffffffff,%edi
  4060ef:	callq  401340 <exit@plt>
  4060f4:	mov    $0x418f20,%edi
  4060f9:	callq  403650 <Error>
  4060fe:	mov    $0x418fb8,%edi
  406103:	callq  401110 <puts@plt>
  406108:	mov    0x23c1c9(%rip),%rcx        # 6422d8 <Global>
  40610f:	lea    0x200878(%rcx),%rdi
  406116:	callq  401180 <pthread_mutex_destroy@plt>
  40611b:	or     $0xffffffff,%edi
  40611e:	callq  401340 <exit@plt>
  406123:	mov    $0x418fb8,%edi
  406128:	callq  401110 <puts@plt>
  40612d:	mov    0x23c1a4(%rip),%rdx        # 6422d8 <Global>
  406134:	lea    0x200810(%rdx),%rdi
  40613b:	callq  401180 <pthread_mutex_destroy@plt>
  406140:	or     $0xffffffff,%edi
  406143:	callq  401340 <exit@plt>
  406148:	nopl   0x0(%rax,%rax,1)

0000000000406150 <Load_Map>:
  406150:	push   %rbp
  406151:	push   %rbx
  406152:	mov    %rdi,%rsi
  406155:	sub    $0xd8,%rsp
  40615c:	mov    %rsp,%rdi
  40615f:	callq  401140 <stpcpy@plt>
  406164:	mov    %rsp,%rdi
  406167:	movl   $0x6e65642e,(%rax)
  40616d:	movb   $0x0,0x4(%rax)
  406171:	callq  403180 <Open_File>
  406176:	mov    $0x64449e,%esi
  40617b:	mov    $0x2,%edx
  406180:	mov    %eax,%edi
  406182:	mov    %eax,%ebx
  406184:	callq  403480 <Read_Shorts>
  406189:	movswl 0x23e30e(%rip),%esi        # 64449e <map_version>
  406190:	cmp    $0x1,%si
  406194:	je     4061a2 <Load_Map+0x52>
  406196:	mov    $0x4191e8,%edi
  40619b:	xor    %eax,%eax
  40619d:	callq  403650 <Error>
  4061a2:	mov    $0x6,%edx
  4061a7:	mov    $0x644492,%esi
  4061ac:	mov    %ebx,%edi
  4061ae:	callq  403480 <Read_Shorts>
  4061b3:	mov    $0x6,%edx
  4061b8:	mov    $0x64448c,%esi
  4061bd:	mov    %ebx,%edi
  4061bf:	callq  403480 <Read_Shorts>
  4061c4:	mov    $0x6,%edx
  4061c9:	mov    $0x6444b4,%esi
  4061ce:	mov    %ebx,%edi
  4061d0:	callq  403480 <Read_Shorts>
  4061d5:	mov    $0x6,%edx
  4061da:	mov    $0x6444a0,%esi
  4061df:	mov    %ebx,%edi
  4061e1:	callq  403480 <Read_Shorts>
  4061e6:	mov    $0x6,%edx
  4061eb:	mov    $0x6444a6,%esi
  4061f0:	mov    %ebx,%edi
  4061f2:	callq  403480 <Read_Shorts>
  4061f7:	mov    $0x6,%edx
  4061fc:	mov    $0x644498,%esi
  406201:	mov    %ebx,%edi
  406203:	callq  403480 <Read_Shorts>
  406208:	mov    $0x6,%edx
  40620d:	mov    $0x644476,%esi
  406212:	mov    %ebx,%edi
  406214:	callq  403480 <Read_Shorts>
  406219:	mov    $0x6,%edx
  40621e:	mov    $0x644470,%esi
  406223:	mov    %ebx,%edi
  406225:	callq  403480 <Read_Shorts>
  40622a:	mov    $0x6,%edx
  40622f:	mov    $0x6444ac,%esi
  406234:	mov    %ebx,%edi
  406236:	callq  403480 <Read_Shorts>
  40623b:	mov    $0x2,%edx
  406240:	mov    $0x6444b2,%esi
  406245:	mov    %ebx,%edi
  406247:	callq  403480 <Read_Shorts>
  40624c:	mov    $0x4,%edx
  406251:	mov    $0x644488,%esi
  406256:	mov    %ebx,%edi
  406258:	callq  403530 <Read_Longs>
  40625d:	movslq 0x23e224(%rip),%rbp        # 644488 <map_length>
  406264:	mov    $0x419208,%edi
  406269:	xor    %eax,%eax
  40626b:	mov    %rbp,%rsi
  40626e:	callq  401170 <printf@plt>
  406273:	mov    %rbp,%rdi
  406276:	callq  401270 <malloc@plt>
  40627b:	test   %rax,%rax
  40627e:	mov    %rax,0x23e1fb(%rip)        # 644480 <map_address>
  406285:	je     4063e8 <Load_Map+0x298>
  40628b:	xor    %edx,%edx
  40628d:	test   %rbp,%rbp
  406290:	jle    4063b2 <Load_Map+0x262>
  406296:	lea    -0x1(%rbp),%rcx
  40629a:	and    $0x7,%ecx
  40629d:	je     4063a5 <Load_Map+0x255>
  4062a3:	cmp    $0x1,%rcx
  4062a7:	movb   $0x0,(%rax)
  4062aa:	mov    $0x1,%edx
  4062af:	mov    0x23e1ca(%rip),%rax        # 644480 <map_address>
  4062b6:	je     4063a5 <Load_Map+0x255>
  4062bc:	cmp    $0x2,%rcx
  4062c0:	je     406326 <Load_Map+0x1d6>
  4062c2:	cmp    $0x3,%rcx
  4062c6:	je     406317 <Load_Map+0x1c7>
  4062c8:	cmp    $0x4,%rcx
  4062cc:	je     406308 <Load_Map+0x1b8>
  4062ce:	cmp    $0x5,%rcx
  4062d2:	je     4062f9 <Load_Map+0x1a9>
  4062d4:	cmp    $0x6,%rcx
  4062d8:	je     4062ea <Load_Map+0x19a>
  4062da:	movb   $0x0,(%rax,%rdx,1)
  4062de:	mov    0x23e19b(%rip),%rax        # 644480 <map_address>
  4062e5:	mov    $0x2,%edx
  4062ea:	movb   $0x0,(%rax,%rdx,1)
  4062ee:	mov    0x23e18b(%rip),%rax        # 644480 <map_address>
  4062f5:	add    $0x1,%rdx
  4062f9:	movb   $0x0,(%rax,%rdx,1)
  4062fd:	mov    0x23e17c(%rip),%rax        # 644480 <map_address>
  406304:	add    $0x1,%rdx
  406308:	movb   $0x0,(%rax,%rdx,1)
  40630c:	mov    0x23e16d(%rip),%rax        # 644480 <map_address>
  406313:	add    $0x1,%rdx
  406317:	movb   $0x0,(%rax,%rdx,1)
  40631b:	mov    0x23e15e(%rip),%rax        # 644480 <map_address>
  406322:	add    $0x1,%rdx
  406326:	movb   $0x0,(%rax,%rdx,1)
  40632a:	mov    0x23e14f(%rip),%rax        # 644480 <map_address>
  406331:	add    $0x1,%rdx
  406335:	movb   $0x0,(%rax,%rdx,1)
  406339:	lea    0x1(%rdx),%rax
  40633d:	cmp    %rax,%rbp
  406340:	je     4063b2 <Load_Map+0x262>
  406342:	mov    0x23e137(%rip),%rsi        # 644480 <map_address>
  406349:	movb   $0x0,0x1(%rsi,%rdx,1)
  40634e:	mov    0x23e12b(%rip),%rdi        # 644480 <map_address>
  406355:	movb   $0x0,0x2(%rdi,%rdx,1)
  40635a:	mov    0x23e11f(%rip),%r8        # 644480 <map_address>
  406361:	movb   $0x0,0x3(%r8,%rdx,1)
  406367:	mov    0x23e112(%rip),%r9        # 644480 <map_address>
  40636e:	movb   $0x0,0x4(%r9,%rdx,1)
  406374:	mov    0x23e105(%rip),%r10        # 644480 <map_address>
  40637b:	movb   $0x0,0x5(%r10,%rdx,1)
  406381:	mov    0x23e0f8(%rip),%r11        # 644480 <map_address>
  406388:	movb   $0x0,0x6(%r11,%rdx,1)
  40638e:	mov    0x23e0eb(%rip),%rcx        # 644480 <map_address>
  406395:	movb   $0x0,0x7(%rcx,%rdx,1)
  40639a:	mov    0x23e0df(%rip),%rax        # 644480 <map_address>
  4063a1:	add    $0x8,%rdx
  4063a5:	movb   $0x0,(%rax,%rdx,1)
  4063a9:	lea    0x1(%rdx),%rax
  4063ad:	cmp    %rax,%rbp
  4063b0:	jne    406342 <Load_Map+0x1f2>
  4063b2:	mov    $0x419260,%edi
  4063b7:	callq  401110 <puts@plt>
  4063bc:	movslq 0x23e0c5(%rip),%rdx        # 644488 <map_length>
  4063c3:	mov    0x23e0b6(%rip),%rsi        # 644480 <map_address>
  4063ca:	mov    %ebx,%edi
  4063cc:	callq  4033d0 <Read_Bytes>
  4063d1:	mov    %ebx,%edi
  4063d3:	callq  4035e0 <Close_File>
  4063d8:	add    $0xd8,%rsp
  4063df:	pop    %rbx
  4063e0:	pop    %rbp
  4063e1:	retq   
  4063e2:	nopw   0x0(%rax,%rax,1)
  4063e8:	mov    $0x419238,%edi
  4063ed:	xor    %eax,%eax
  4063ef:	callq  403650 <Error>
  4063f4:	jmp    4063b2 <Load_Map+0x262>
  4063f6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000406400 <Allocate_Map>:
  406400:	push   %rbp
  406401:	push   %rbx
  406402:	mov    %rsi,%rbp
  406405:	mov    %rdi,%rbx
  406408:	xor    %eax,%eax
  40640a:	mov    $0x419208,%edi
  40640f:	sub    $0x8,%rsp
  406413:	callq  401170 <printf@plt>
  406418:	mov    %rbp,%rdi
  40641b:	callq  401270 <malloc@plt>
  406420:	test   %rax,%rax
  406423:	mov    %rax,(%rbx)
  406426:	je     406520 <Allocate_Map+0x120>
  40642c:	xor    %edx,%edx
  40642e:	test   %rbp,%rbp
  406431:	jle    406517 <Allocate_Map+0x117>
  406437:	lea    -0x1(%rbp),%rcx
  40643b:	and    $0x7,%ecx
  40643e:	je     40650a <Allocate_Map+0x10a>
  406444:	cmp    $0x1,%rcx
  406448:	movb   $0x0,(%rax)
  40644b:	mov    $0x1,%edx
  406450:	mov    (%rbx),%rax
  406453:	je     40650a <Allocate_Map+0x10a>
  406459:	cmp    $0x2,%rcx
  40645d:	je     4064af <Allocate_Map+0xaf>
  40645f:	cmp    $0x3,%rcx
  406463:	je     4064a4 <Allocate_Map+0xa4>
  406465:	cmp    $0x4,%rcx
  406469:	je     406499 <Allocate_Map+0x99>
  40646b:	cmp    $0x5,%rcx
  40646f:	je     40648e <Allocate_Map+0x8e>
  406471:	cmp    $0x6,%rcx
  406475:	je     406483 <Allocate_Map+0x83>
  406477:	movb   $0x0,(%rax,%rdx,1)
  40647b:	mov    (%rbx),%rax
  40647e:	mov    $0x2,%edx
  406483:	movb   $0x0,(%rax,%rdx,1)
  406487:	mov    (%rbx),%rax
  40648a:	add    $0x1,%rdx
  40648e:	movb   $0x0,(%rax,%rdx,1)
  406492:	mov    (%rbx),%rax
  406495:	add    $0x1,%rdx
  406499:	movb   $0x0,(%rax,%rdx,1)
  40649d:	mov    (%rbx),%rax
  4064a0:	add    $0x1,%rdx
  4064a4:	movb   $0x0,(%rax,%rdx,1)
  4064a8:	mov    (%rbx),%rax
  4064ab:	add    $0x1,%rdx
  4064af:	movb   $0x0,(%rax,%rdx,1)
  4064b3:	mov    (%rbx),%rax
  4064b6:	add    $0x1,%rdx
  4064ba:	movb   $0x0,(%rax,%rdx,1)
  4064be:	lea    0x1(%rdx),%rax
  4064c2:	cmp    %rax,%rbp
  4064c5:	je     406517 <Allocate_Map+0x117>
  4064c7:	mov    (%rbx),%rsi
  4064ca:	movb   $0x0,0x1(%rsi,%rdx,1)
  4064cf:	mov    (%rbx),%rdi
  4064d2:	movb   $0x0,0x2(%rdi,%rdx,1)
  4064d7:	mov    (%rbx),%r8
  4064da:	movb   $0x0,0x3(%r8,%rdx,1)
  4064e0:	mov    (%rbx),%r9
  4064e3:	movb   $0x0,0x4(%r9,%rdx,1)
  4064e9:	mov    (%rbx),%r10
  4064ec:	movb   $0x0,0x5(%r10,%rdx,1)
  4064f2:	mov    (%rbx),%r11
  4064f5:	movb   $0x0,0x6(%r11,%rdx,1)
  4064fb:	mov    (%rbx),%rcx
  4064fe:	movb   $0x0,0x7(%rcx,%rdx,1)
  406503:	mov    (%rbx),%rax
  406506:	add    $0x8,%rdx
  40650a:	movb   $0x0,(%rax,%rdx,1)
  40650e:	lea    0x1(%rdx),%rax
  406512:	cmp    %rax,%rbp
  406515:	jne    4064c7 <Allocate_Map+0xc7>
  406517:	add    $0x8,%rsp
  40651b:	pop    %rbx
  40651c:	pop    %rbp
  40651d:	retq   
  40651e:	xchg   %ax,%ax
  406520:	add    $0x8,%rsp
  406524:	mov    $0x419238,%edi
  406529:	xor    %eax,%eax
  40652b:	pop    %rbx
  40652c:	pop    %rbp
  40652d:	jmpq   403650 <Error>
  406532:	nopl   0x0(%rax)
  406536:	nopw   %cs:0x0(%rax,%rax,1)

0000000000406540 <Deallocate_Map>:
  406540:	push   %rbx
  406541:	mov    %rdi,%rbx
  406544:	mov    $0x419288,%edi
  406549:	callq  401110 <puts@plt>
  40654e:	movq   $0x0,(%rbx)
  406555:	pop    %rbx
  406556:	retq   
  406557:	nopw   0x0(%rax,%rax,1)

0000000000406560 <Allocate_Normal>:
  406560:	push   %r12
  406562:	push   %rbp
  406563:	mov    %rdi,%r12
  406566:	push   %rbx
  406567:	lea    (%rsi,%rsi,1),%rbx
  40656b:	mov    $0x4192a8,%edi
  406570:	xor    %eax,%eax
  406572:	mov    %rsi,%rbp
  406575:	mov    %rbx,%rsi
  406578:	callq  401170 <printf@plt>
  40657d:	mov    %rbx,%rdi
  406580:	callq  401270 <malloc@plt>
  406585:	test   %rax,%rax
  406588:	mov    %rax,(%r12)
  40658c:	je     4065b0 <Allocate_Normal+0x50>
  40658e:	test   %rbp,%rbp
  406591:	jle    4065a8 <Allocate_Normal+0x48>
  406593:	mov    (%r12),%rdi
  406597:	mov    %rbx,%rdx
  40659a:	xor    %esi,%esi
  40659c:	pop    %rbx
  40659d:	pop    %rbp
  40659e:	pop    %r12
  4065a0:	jmpq   4011c0 <memset@plt>
  4065a5:	nopl   (%rax)
  4065a8:	pop    %rbx
  4065a9:	pop    %rbp
  4065aa:	pop    %r12
  4065ac:	retq   
  4065ad:	nopl   (%rax)
  4065b0:	mov    $0x419238,%edi
  4065b5:	callq  403650 <Error>
  4065ba:	jmp    40658e <Allocate_Normal+0x2e>
  4065bc:	nopl   0x0(%rax)

00000000004065c0 <Normal_Compute>:
  4065c0:	push   %r15
  4065c2:	push   %r14
  4065c4:	push   %r13
  4065c6:	push   %r12
  4065c8:	push   %rbp
  4065c9:	push   %rbx
  4065ca:	sub    $0x68,%rsp
  4065ce:	mov    0x23bd03(%rip),%rax        # 6422d8 <Global>
  4065d5:	lea    0x2008e0(%rax),%rdi
  4065dc:	callq  401380 <pthread_mutex_lock@plt>
  4065e1:	mov    0x23bcf0(%rip),%rcx        # 6422d8 <Global>
  4065e8:	mov    (%rcx),%rdx
  4065eb:	lea    0x2008e0(%rcx),%rdi
  4065f2:	add    $0x1,%rdx
  4065f6:	mov    %rdx,(%rcx)
  4065f9:	callq  401260 <pthread_mutex_unlock@plt>
  4065fe:	pxor   %xmm0,%xmm0
  406602:	movswq 0x23dece(%rip),%rbx        # 6444d8 <norm_len+0x4>
  40660a:	movswq 0x23dec2(%rip),%rdi        # 6444d4 <norm_len>
  406612:	movswq 0x23debc(%rip),%r10        # 6444d6 <norm_len+0x2>
  40661a:	cvtsi2ssq 0x23eb6d(%rip),%xmm0        # 645190 <magnitude_epsilon>
  406623:	test   %bx,%bx
  406626:	mov    %rdi,(%rsp)
  40662a:	mov    %r10,0x8(%rsp)
  40662f:	movss  %xmm0,0x23de8d(%rip)        # 6444c4 <nmag_epsilon>
  406637:	jle    406848 <Normal_Compute+0x288>
  40663d:	test   %r10,%r10
  406640:	jle    406848 <Normal_Compute+0x288>
  406646:	test   %rdi,%rdi
  406649:	jle    406848 <Normal_Compute+0x288>
  40664f:	pxor   %xmm6,%xmm6
  406653:	add    $0x2,%rbx
  406657:	mov    $0x2,%r15d
  40665d:	movsd  0x127ab(%rip),%xmm5        # 418e10 <__dso_handle+0x48>
  406665:	mov    %rbx,0x10(%rsp)
  40666a:	movsd  0x12cfe(%rip),%xmm7        # 419370 <__dso_handle+0x5a8>
  406672:	nopw   0x0(%rax,%rax,1)
  406678:	lea    -0x2(%r15),%r13
  40667c:	lea    -0x1(%r15),%r11
  406680:	xor    %r12d,%r12d
  406683:	nopl   0x0(%rax,%rax,1)
  406688:	lea    0x1(%r12),%rbp
  40668d:	lea    0x2(%r12),%r14
  406692:	xor    %ebx,%ebx
  406694:	jmp    4066c4 <Normal_Compute+0x104>
  406696:	nopw   %cs:0x0(%rax,%rax,1)
  4066a0:	cmp    %rbx,(%rsp)
  4066a4:	mov    $0x1ec7,%r8d
  4066aa:	mov    %r8w,(%rax)
  4066ae:	je     406806 <Normal_Compute+0x246>
  4066b4:	movswq 0x23de18(%rip),%rdi        # 6444d4 <norm_len>
  4066bc:	movswq 0x23de12(%rip),%r10        # 6444d6 <norm_len+0x2>
  4066c4:	movswq 0x23dde2(%rip),%rax        # 6444ae <map_len+0x2>
  4066cc:	movswq 0x23ddd8(%rip),%r8        # 6444ac <map_len>
  4066d4:	add    $0x1,%rbx
  4066d8:	mov    0x23dda1(%rip),%rdx        # 644480 <map_address>
  4066df:	pxor   %xmm3,%xmm3
  4066e3:	pxor   %xmm4,%xmm4
  4066e7:	pxor   %xmm2,%xmm2
  4066eb:	mov    %rax,%rcx
  4066ee:	imul   %r11,%rcx
  4066f2:	imul   %r13,%r10
  4066f6:	lea    (%rcx,%rbp,1),%rsi
  4066fa:	add    %r12,%r10
  4066fd:	imul   %r8,%rsi
  406701:	imul   %r10,%rdi
  406705:	mov    0x23ddbc(%rip),%r10        # 6444c8 <norm_address>
  40670c:	add    %rbx,%rsi
  40670f:	movzbl 0x1(%rdx,%rsi,1),%r9d
  406715:	movzbl -0x1(%rdx,%rsi,1),%esi
  40671a:	add    %rbx,%rdx
  40671d:	lea    -0x1(%rbx,%rdi,1),%rdi
  406722:	sub    %rsi,%r9
  406725:	cvtsi2sd %r9,%xmm3
  40672a:	lea    (%rcx,%r14,1),%r9
  40672e:	add    %r12,%rcx
  406731:	imul   %r8,%rcx
  406735:	imul   %r8,%r9
  406739:	movzbl (%rdx,%rcx,1),%ecx
  40673d:	movzbl (%rdx,%r9,1),%esi
  406742:	mov    %rax,%r9
  406745:	imul   %r15,%r9
  406749:	imul   %r13,%rax
  40674d:	sub    %rcx,%rsi
  406750:	add    %rbp,%r9
  406753:	cvtsi2sd %rsi,%xmm4
  406758:	add    %rbp,%rax
  40675b:	movapd %xmm3,%xmm1
  40675f:	imul   %r8,%r9
  406763:	imul   %rax,%r8
  406767:	mulsd  %xmm3,%xmm1
  40676b:	lea    (%r10,%rdi,2),%rax
  40676f:	movzbl (%rdx,%r9,1),%esi
  406774:	movzbl (%rdx,%r8,1),%edx
  406779:	sub    %rdx,%rsi
  40677c:	movapd %xmm4,%xmm0
  406780:	cvtsi2sd %rsi,%xmm2
  406785:	mulsd  %xmm4,%xmm0
  406789:	addsd  %xmm1,%xmm0
  40678d:	movapd %xmm2,%xmm8
  406792:	mulsd  %xmm2,%xmm8
  406797:	addsd  %xmm8,%xmm0
  40679c:	ucomisd %xmm5,%xmm0
  4067a0:	jbe    4066a0 <Normal_Compute+0xe0>
  4067a6:	ucomisd %xmm0,%xmm6
  4067aa:	sqrtsd %xmm0,%xmm9
  4067af:	ja     406857 <Normal_Compute+0x297>
  4067b5:	movapd %xmm7,%xmm10
  4067ba:	xor    %edi,%edi
  4067bc:	divsd  %xmm9,%xmm10
  4067c1:	mulsd  %xmm10,%xmm2
  4067c6:	mulsd  %xmm10,%xmm4
  4067cb:	mulsd  %xmm10,%xmm3
  4067d0:	cvttsd2si %xmm2,%r9
  4067d5:	cvttsd2si %xmm4,%rsi
  4067da:	mov    %r9,%rcx
  4067dd:	shl    $0x6,%rcx
  4067e1:	sub    %r9,%rcx
  4067e4:	ucomisd %xmm6,%xmm3
  4067e8:	lea    0x7c0(%rcx,%rsi,1),%rdx
  4067f0:	seta   %dil
  4067f4:	cmp    %rbx,(%rsp)
  4067f8:	lea    (%rdi,%rdx,2),%r10d
  4067fc:	mov    %r10w,(%rax)
  406800:	jne    4066b4 <Normal_Compute+0xf4>
  406806:	cmp    %rbp,0x8(%rsp)
  40680b:	mov    %rbp,%r12
  40680e:	je     406828 <Normal_Compute+0x268>
  406810:	movswq 0x23dcbc(%rip),%rdi        # 6444d4 <norm_len>
  406818:	movswq 0x23dcb6(%rip),%r10        # 6444d6 <norm_len+0x2>
  406820:	jmpq   406688 <Normal_Compute+0xc8>
  406825:	nopl   (%rax)
  406828:	add    $0x1,%r15
  40682c:	cmp    %r15,0x10(%rsp)
  406831:	je     406848 <Normal_Compute+0x288>
  406833:	movswq 0x23dc99(%rip),%rdi        # 6444d4 <norm_len>
  40683b:	movswq 0x23dc93(%rip),%r10        # 6444d6 <norm_len+0x2>
  406843:	jmpq   406678 <Normal_Compute+0xb8>
  406848:	add    $0x68,%rsp
  40684c:	pop    %rbx
  40684d:	pop    %rbp
  40684e:	pop    %r12
  406850:	pop    %r13
  406852:	pop    %r14
  406854:	pop    %r15
  406856:	retq   
  406857:	mov    %r11,0x58(%rsp)
  40685c:	movsd  %xmm7,0x50(%rsp)
  406862:	mov    %rax,0x38(%rsp)
  406867:	movsd  %xmm6,0x48(%rsp)
  40686d:	movsd  %xmm5,0x40(%rsp)
  406873:	movsd  %xmm2,0x30(%rsp)
  406879:	movsd  %xmm4,0x28(%rsp)
  40687f:	movsd  %xmm3,0x20(%rsp)
  406885:	movsd  %xmm9,0x18(%rsp)
  40688c:	callq  401360 <sqrt@plt>
  406891:	mov    0x58(%rsp),%r11
  406896:	movsd  0x50(%rsp),%xmm7
  40689c:	mov    0x38(%rsp),%rax
  4068a1:	movsd  0x48(%rsp),%xmm6
  4068a7:	movsd  0x40(%rsp),%xmm5
  4068ad:	movsd  0x30(%rsp),%xmm2
  4068b3:	movsd  0x28(%rsp),%xmm4
  4068b9:	movsd  0x20(%rsp),%xmm3
  4068bf:	movsd  0x18(%rsp),%xmm9
  4068c6:	jmpq   4067b5 <Normal_Compute+0x1f5>
  4068cb:	nopl   0x0(%rax,%rax,1)

00000000004068d0 <Compute_Normal>:
  4068d0:	push   %rbp
  4068d1:	push   %rbx
  4068d2:	sub    $0x8,%rsp
  4068d6:	movzwl 0x23dbd1(%rip),%esi        # 6444ae <map_len+0x2>
  4068dd:	movzwl 0x23dbc8(%rip),%eax        # 6444ac <map_len>
  4068e4:	movzwl 0x23dbc5(%rip),%edx        # 6444b0 <map_len+0x4>
  4068eb:	lea    -0x2(%rsi),%ecx
  4068ee:	sub    $0x2,%eax
  4068f1:	movswl %ax,%ebx
  4068f4:	lea    -0x2(%rdx),%edi
  4068f7:	mov    %ax,0x23dbd6(%rip)        # 6444d4 <norm_len>
  4068fe:	movswl %cx,%ebp
  406901:	xor    %eax,%eax
  406903:	mov    %cx,0x23dbcc(%rip)        # 6444d6 <norm_len+0x2>
  40690a:	imul   %ebp,%ebx
  40690d:	movswl %di,%r8d
  406911:	mov    %di,0x23dbc0(%rip)        # 6444d8 <norm_len+0x4>
  406918:	mov    $0x4192a8,%edi
  40691d:	imul   %r8d,%ebx
  406921:	movslq %ebx,%rbp
  406924:	mov    %ebx,0x23dba6(%rip)        # 6444d0 <norm_length>
  40692a:	add    %rbp,%rbp
  40692d:	mov    %rbp,%rsi
  406930:	callq  401170 <printf@plt>
  406935:	mov    %rbp,%rdi
  406938:	callq  401270 <malloc@plt>
  40693d:	test   %rax,%rax
  406940:	mov    %rax,0x23db81(%rip)        # 6444c8 <norm_address>
  406947:	je     406988 <Compute_Normal+0xb8>
  406949:	test   %ebx,%ebx
  40694b:	jle    40695e <Compute_Normal+0x8e>
  40694d:	mov    0x23db74(%rip),%rdi        # 6444c8 <norm_address>
  406954:	mov    %rbp,%rdx
  406957:	xor    %esi,%esi
  406959:	callq  4011c0 <memset@plt>
  40695e:	mov    $0x419357,%edi
  406963:	callq  401110 <puts@plt>
  406968:	mov    0x23b969(%rip),%r9        # 6422d8 <Global>
  40696f:	movq   $0x0,(%r9)
  406976:	add    $0x8,%rsp
  40697a:	pop    %rbx
  40697b:	pop    %rbp
  40697c:	jmpq   4065c0 <Normal_Compute>
  406981:	nopl   0x0(%rax)
  406988:	mov    $0x419238,%edi
  40698d:	callq  403650 <Error>
  406992:	jmp    406949 <Compute_Normal+0x79>
  406994:	xchg   %ax,%ax
  406996:	nopw   %cs:0x0(%rax,%rax,1)

00000000004069a0 <Load_Normal>:
  4069a0:	push   %r12
  4069a2:	push   %rbp
  4069a3:	mov    %rdi,%rsi
  4069a6:	push   %rbx
  4069a7:	sub    $0xd0,%rsp
  4069ae:	mov    %rsp,%rdi
  4069b1:	callq  401140 <stpcpy@plt>
  4069b6:	mov    $0x6d,%edx
  4069bb:	mov    %rsp,%rdi
  4069be:	movl   $0x726f6e2e,(%rax)
  4069c4:	mov    %dx,0x4(%rax)
  4069c8:	callq  403180 <Open_File>
  4069cd:	mov    $0x6444c0,%esi
  4069d2:	mov    $0x2,%edx
  4069d7:	mov    %eax,%edi
  4069d9:	mov    %eax,%ebx
  4069db:	callq  403480 <Read_Shorts>
  4069e0:	movswl 0x23dad9(%rip),%esi        # 6444c0 <norm_version>
  4069e7:	cmp    $0x1,%si
  4069eb:	je     4069f9 <Load_Normal+0x59>
  4069ed:	mov    $0x4191e8,%edi
  4069f2:	xor    %eax,%eax
  4069f4:	callq  403650 <Error>
  4069f9:	mov    $0x6,%edx
  4069fe:	mov    $0x6444d4,%esi
  406a03:	mov    %ebx,%edi
  406a05:	callq  403480 <Read_Shorts>
  406a0a:	mov    $0x4,%edx
  406a0f:	mov    $0x6444d0,%esi
  406a14:	mov    %ebx,%edi
  406a16:	callq  403530 <Read_Longs>
  406a1b:	movslq 0x23daae(%rip),%rbp        # 6444d0 <norm_length>
  406a22:	mov    $0x4192a8,%edi
  406a27:	xor    %eax,%eax
  406a29:	mov    %rbp,%r12
  406a2c:	add    %rbp,%rbp
  406a2f:	mov    %rbp,%rsi
  406a32:	callq  401170 <printf@plt>
  406a37:	mov    %rbp,%rdi
  406a3a:	callq  401270 <malloc@plt>
  406a3f:	test   %rax,%rax
  406a42:	mov    %rax,0x23da7f(%rip)        # 6444c8 <norm_address>
  406a49:	je     406aa8 <Load_Normal+0x108>
  406a4b:	test   %r12d,%r12d
  406a4e:	jle    406a61 <Load_Normal+0xc1>
  406a50:	mov    0x23da71(%rip),%rdi        # 6444c8 <norm_address>
  406a57:	mov    %rbp,%rdx
  406a5a:	xor    %esi,%esi
  406a5c:	callq  4011c0 <memset@plt>
  406a61:	mov    $0x4192d8,%edi
  406a66:	callq  401110 <puts@plt>
  406a6b:	movslq 0x23da5e(%rip),%rdx        # 6444d0 <norm_length>
  406a72:	mov    0x23da4f(%rip),%rsi        # 6444c8 <norm_address>
  406a79:	mov    %ebx,%edi
  406a7b:	add    %rdx,%rdx
  406a7e:	callq  403480 <Read_Shorts>
  406a83:	mov    0x23b6f6(%rip),%rdi        # 642180 <stdout@@GLIBC_2.2.5>
  406a8a:	callq  401280 <fflush@plt>
  406a8f:	mov    %ebx,%edi
  406a91:	callq  4035e0 <Close_File>
  406a96:	add    $0xd0,%rsp
  406a9d:	pop    %rbx
  406a9e:	pop    %rbp
  406a9f:	pop    %r12
  406aa1:	retq   
  406aa2:	nopw   0x0(%rax,%rax,1)
  406aa8:	mov    $0x419238,%edi
  406aad:	callq  403650 <Error>
  406ab2:	jmp    406a4b <Load_Normal+0xab>
  406ab4:	xchg   %ax,%ax
  406ab6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000406ac0 <Store_Normal>:
  406ac0:	push   %rbx
  406ac1:	mov    %rdi,%rsi
  406ac4:	mov    %rdi,%rbx
  406ac7:	sub    $0xd0,%rsp
  406ace:	mov    %rsp,%rdi
  406ad1:	callq  401140 <stpcpy@plt>
  406ad6:	mov    $0x6d,%edx
  406adb:	mov    %rsp,%rdi
  406ade:	movl   $0x726f6e2e,(%rax)
  406ae4:	mov    %dx,0x4(%rax)
  406ae8:	callq  403140 <Create_File>
  406aed:	mov    $0x1,%ecx
  406af2:	mov    %rbx,%rsi
  406af5:	mov    %rsp,%rdi
  406af8:	mov    %cx,0x23d9c1(%rip)        # 6444c0 <norm_version>
  406aff:	callq  401140 <stpcpy@plt>
  406b04:	mov    $0x6d,%esi
  406b09:	mov    %rsp,%rdi
  406b0c:	movl   $0x726f6e2e,(%rax)
  406b12:	mov    %si,0x4(%rax)
  406b16:	callq  403140 <Create_File>
  406b1b:	mov    $0x2,%edx
  406b20:	mov    %eax,%ebx
  406b22:	mov    %eax,%edi
  406b24:	mov    $0x6444c0,%esi
  406b29:	callq  403270 <Write_Shorts>
  406b2e:	mov    %ebx,%edi
  406b30:	mov    $0x6,%edx
  406b35:	mov    $0x6444d4,%esi
  406b3a:	callq  403270 <Write_Shorts>
  406b3f:	mov    $0x4,%edx
  406b44:	mov    $0x6444d0,%esi
  406b49:	mov    %ebx,%edi
  406b4b:	callq  403320 <Write_Longs>
  406b50:	mov    $0x419308,%edi
  406b55:	callq  401110 <puts@plt>
  406b5a:	movslq 0x23d96f(%rip),%rdx        # 6444d0 <norm_length>
  406b61:	mov    0x23d960(%rip),%rsi        # 6444c8 <norm_address>
  406b68:	mov    %ebx,%edi
  406b6a:	add    %rdx,%rdx
  406b6d:	callq  403270 <Write_Shorts>
  406b72:	mov    %ebx,%edi
  406b74:	callq  4035e0 <Close_File>
  406b79:	add    $0xd0,%rsp
  406b80:	pop    %rbx
  406b81:	retq   
  406b82:	nopl   0x0(%rax)
  406b86:	nopw   %cs:0x0(%rax,%rax,1)

0000000000406b90 <Deallocate_Normal>:
  406b90:	push   %rbx
  406b91:	mov    %rdi,%rbx
  406b94:	mov    $0x419338,%edi
  406b99:	callq  401110 <puts@plt>
  406b9e:	movq   $0x0,(%rbx)
  406ba5:	pop    %rbx
  406ba6:	retq   
  406ba7:	nopw   0x0(%rax,%rax,1)

0000000000406bb0 <Compute_Base>:
  406bb0:	mov    0x23b721(%rip),%rax        # 6422d8 <Global>
  406bb7:	push   %r12
  406bb9:	push   %rbp
  406bba:	push   %rbx
  406bbb:	lea    0x2008e0(%rax),%rdi
  406bc2:	callq  401380 <pthread_mutex_lock@plt>
  406bc7:	mov    0x23b70a(%rip),%rcx        # 6422d8 <Global>
  406bce:	mov    (%rcx),%rdx
  406bd1:	lea    0x2008e0(%rcx),%rdi
  406bd8:	add    $0x1,%rdx
  406bdc:	mov    %rdx,(%rcx)
  406bdf:	callq  401260 <pthread_mutex_unlock@plt>
  406be4:	movswq 0x23d918(%rip),%r11        # 644504 <pyr_len+0x4>
  406bec:	movswq 0x23d90c(%rip),%rcx        # 644500 <pyr_len>
  406bf4:	movswq 0x23d906(%rip),%rbp        # 644502 <pyr_len+0x2>
  406bfc:	test   %r11,%r11
  406bff:	jle    406df0 <Compute_Base+0x240>
  406c05:	test   %rbp,%rbp
  406c08:	jle    406df0 <Compute_Base+0x240>
  406c0e:	xor    %edi,%edi
  406c10:	test   %rcx,%rcx
  406c13:	mov    %rcx,%r8
  406c16:	mov    %rbp,%r10
  406c19:	mov    $0x1,%r9d
  406c1f:	jle    406df0 <Compute_Base+0x240>
  406c25:	nopl   (%rax)
  406c28:	xor    %esi,%esi
  406c2a:	nopw   0x0(%rax,%rax,1)
  406c30:	xor    %ebx,%ebx
  406c32:	test   $0x1,%r8b
  406c36:	jne    406ce9 <Compute_Base+0x139>
  406c3c:	movswq 0x23d9ce(%rip),%rdx        # 644612 <opc_len+0x2>
  406c44:	imul   %rdi,%rbp
  406c48:	imul   %rdi,%rdx
  406c4c:	lea    0x0(%rbp,%rsi,1),%rax
  406c51:	movswq 0x23d9b7(%rip),%rbp        # 644610 <opc_len>
  406c59:	mov    %rax,%r12
  406c5c:	add    %rsi,%rdx
  406c5f:	imul   %rcx,%r12
  406c63:	imul   %rbp,%rdx
  406c67:	add    0x23d9b2(%rip),%rdx        # 644620 <opc_address>
  406c6e:	mov    %r12,%rcx
  406c71:	mov    %r12,%rbx
  406c74:	and    $0x7,%ecx
  406c77:	sar    $0x3,%rbx
  406c7b:	add    0x23d93e(%rip),%rbx        # 6445c0 <pyr_address>
  406c82:	cmpb   $0x0,(%rdx)
  406c85:	mov    %r12,0x23d854(%rip)        # 6444e0 <pyr_offset1>
  406c8c:	mov    %rcx,0x23d91d(%rip)        # 6445b0 <pyr_offset2>
  406c93:	mov    %rbx,0x23d84e(%rip)        # 6444e8 <pyr_address2>
  406c9a:	je     406ca3 <Compute_Base+0xf3>
  406c9c:	mov    %r9d,%eax
  406c9f:	shl    %cl,%eax
  406ca1:	or     %al,(%rbx)
  406ca3:	mov    $0x1,%ebx
  406ca8:	movswq 0x23d850(%rip),%rcx        # 644500 <pyr_len>
  406cb0:	movswq 0x23d84a(%rip),%rbp        # 644502 <pyr_len+0x2>
  406cb8:	jmp    406ce9 <Compute_Base+0x139>
  406cba:	nopw   0x0(%rax,%rax,1)
  406cc0:	mov    %rax,0x23d819(%rip)        # 6444e0 <pyr_offset1>
  406cc7:	mov    %rcx,0x23d8e2(%rip)        # 6445b0 <pyr_offset2>
  406cce:	mov    %rbp,0x23d813(%rip)        # 6444e8 <pyr_address2>
  406cd5:	movswq 0x23d823(%rip),%rcx        # 644500 <pyr_len>
  406cdd:	movswq 0x23d81d(%rip),%rbp        # 644502 <pyr_len+0x2>
  406ce5:	add    $0x1,%rbx
  406ce9:	movswq 0x23d921(%rip),%rdx        # 644612 <opc_len+0x2>
  406cf1:	movswq 0x23d917(%rip),%r12        # 644610 <opc_len>
  406cf9:	imul   %rdi,%rbp
  406cfd:	imul   %rdi,%rdx
  406d01:	lea    0x0(%rbp,%rsi,1),%rax
  406d06:	imul   %rcx,%rax
  406d0a:	add    %rsi,%rdx
  406d0d:	imul   %r12,%rdx
  406d11:	mov    0x23d908(%rip),%r12        # 644620 <opc_address>
  406d18:	add    %rbx,%rax
  406d1b:	mov    %rax,%rcx
  406d1e:	mov    %rax,%rbp
  406d21:	and    $0x7,%ecx
  406d24:	sar    $0x3,%rbp
  406d28:	add    0x23d891(%rip),%rbp        # 6445c0 <pyr_address>
  406d2f:	add    %rbx,%r12
  406d32:	cmpb   $0x0,(%r12,%rdx,1)
  406d37:	mov    %rax,0x23d7a2(%rip)        # 6444e0 <pyr_offset1>
  406d3e:	mov    %rcx,0x23d86b(%rip)        # 6445b0 <pyr_offset2>
  406d45:	mov    %rbp,0x23d79c(%rip)        # 6444e8 <pyr_address2>
  406d4c:	je     406d56 <Compute_Base+0x1a6>
  406d4e:	mov    %r9d,%eax
  406d51:	shl    %cl,%eax
  406d53:	or     %al,0x0(%rbp)
  406d56:	add    $0x1,%rbx
  406d5a:	cmp    %rbx,%r8
  406d5d:	je     406df8 <Compute_Base+0x248>
  406d63:	movswq 0x23d797(%rip),%rdx        # 644502 <pyr_len+0x2>
  406d6b:	movswq 0x23d78d(%rip),%rcx        # 644500 <pyr_len>
  406d73:	movswq 0x23d895(%rip),%r12        # 644610 <opc_len>
  406d7b:	imul   %rdi,%rdx
  406d7f:	lea    (%rdx,%rsi,1),%rax
  406d83:	movswq 0x23d887(%rip),%rdx        # 644612 <opc_len+0x2>
  406d8b:	imul   %rcx,%rax
  406d8f:	imul   %rdi,%rdx
  406d93:	add    %rbx,%rax
  406d96:	mov    %rax,%rcx
  406d99:	mov    %rax,%rbp
  406d9c:	add    %rsi,%rdx
  406d9f:	sar    $0x3,%rbp
  406da3:	and    $0x7,%ecx
  406da6:	imul   %r12,%rdx
  406daa:	mov    0x23d86f(%rip),%r12        # 644620 <opc_address>
  406db1:	add    0x23d808(%rip),%rbp        # 6445c0 <pyr_address>
  406db8:	add    %rbx,%r12
  406dbb:	cmpb   $0x0,(%r12,%rdx,1)
  406dc0:	je     406cc0 <Compute_Base+0x110>
  406dc6:	mov    %rax,0x23d713(%rip)        # 6444e0 <pyr_offset1>
  406dcd:	mov    %r9d,%eax
  406dd0:	mov    %rcx,0x23d7d9(%rip)        # 6445b0 <pyr_offset2>
  406dd7:	mov    %rbp,0x23d70a(%rip)        # 6444e8 <pyr_address2>
  406dde:	shl    %cl,%eax
  406de0:	or     %al,0x0(%rbp)
  406de3:	jmpq   406cd5 <Compute_Base+0x125>
  406de8:	nopl   0x0(%rax,%rax,1)
  406df0:	pop    %rbx
  406df1:	pop    %rbp
  406df2:	pop    %r12
  406df4:	retq   
  406df5:	nopl   (%rax)
  406df8:	add    $0x1,%rsi
  406dfc:	cmp    %rsi,%r10
  406dff:	je     406e20 <Compute_Base+0x270>
  406e01:	movswq 0x23d6f7(%rip),%rcx        # 644500 <pyr_len>
  406e09:	movswq 0x23d6f1(%rip),%rbp        # 644502 <pyr_len+0x2>
  406e11:	jmpq   406c30 <Compute_Base+0x80>
  406e16:	nopw   %cs:0x0(%rax,%rax,1)
  406e20:	add    $0x1,%rdi
  406e24:	cmp    %rdi,%r11
  406e27:	je     406df0 <Compute_Base+0x240>
  406e29:	movswq 0x23d6cf(%rip),%rcx        # 644500 <pyr_len>
  406e31:	movswq 0x23d6c9(%rip),%rbp        # 644502 <pyr_len+0x2>
  406e39:	jmpq   406c28 <Compute_Base+0x78>
  406e3e:	xchg   %ax,%ax

0000000000406e40 <Or_Neighbors_In_Base>:
  406e40:	push   %r15
  406e42:	push   %r14
  406e44:	push   %r13
  406e46:	push   %r12
  406e48:	push   %rbp
  406e49:	push   %rbx
  406e4a:	sub    $0x48,%rsp
  406e4e:	mov    0x23b483(%rip),%rax        # 6422d8 <Global>
  406e55:	lea    0x2008e0(%rax),%rdi
  406e5c:	callq  401380 <pthread_mutex_lock@plt>
  406e61:	mov    0x23b470(%rip),%rcx        # 6422d8 <Global>
  406e68:	mov    (%rcx),%rdx
  406e6b:	lea    0x2008e0(%rcx),%rdi
  406e72:	add    $0x1,%rdx
  406e76:	mov    %rdx,(%rcx)
  406e79:	callq  401260 <pthread_mutex_unlock@plt>
  406e7e:	movswq 0x23d67e(%rip),%rbx        # 644504 <pyr_len+0x4>
  406e86:	test   %rbx,%rbx
  406e89:	mov    %rbx,0x38(%rsp)
  406e8e:	jle    40718a <Or_Neighbors_In_Base+0x34a>
  406e94:	mov    %rbx,%rbp
  406e97:	movswq 0x23d663(%rip),%rbx        # 644502 <pyr_len+0x2>
  406e9f:	movq   $0x0,0x18(%rsp)
  406ea8:	mov    0x18(%rsp),%rdi
  406ead:	mov    %rbx,%r15
  406eb0:	sub    $0x1,%ebp
  406eb3:	add    $0x1,%rdi
  406eb7:	movq   $0x0,(%rsp)
  406ebf:	movslq %ebp,%rsi
  406ec2:	mov    %rdi,0x30(%rsp)
  406ec7:	cmp    %rdi,%rsi
  406eca:	cmovg  %rdi,%rsi
  406ece:	cmp    (%rsp),%rbx
  406ed2:	mov    %rsi,0x20(%rsp)
  406ed7:	jle    40716d <Or_Neighbors_In_Base+0x32d>
  406edd:	nopl   (%rax)
  406ee0:	mov    (%rsp),%r8
  406ee4:	movswq 0x23d614(%rip),%r13        # 644500 <pyr_len>
  406eec:	movswl %r15w,%r10d
  406ef0:	sub    $0x1,%r10d
  406ef4:	movslq %r10d,%r11
  406ef7:	lea    0x1(%r8),%r9
  406efb:	mov    %r13,%rdx
  406efe:	cmp    %r9,%r11
  406f01:	mov    %r9,0x28(%rsp)
  406f06:	cmovg  %r9,%r11
  406f0a:	test   %r13,%r13
  406f0d:	mov    %r11,0x8(%rsp)
  406f12:	jle    40715a <Or_Neighbors_In_Base+0x31a>
  406f18:	xor    %r11d,%r11d
  406f1b:	jmp    406f2b <Or_Neighbors_In_Base+0xeb>
  406f1d:	nopl   (%rax)
  406f20:	movswq 0x23d5da(%rip),%rbx        # 644502 <pyr_len+0x2>
  406f28:	mov    %r15,%r11
  406f2b:	movswl %dx,%r12d
  406f2f:	lea    0x1(%r11),%r15
  406f33:	mov    0x18(%rsp),%rax
  406f38:	sub    $0x1,%r12d
  406f3c:	mov    (%rsp),%r14
  406f40:	mov    0x23d679(%rip),%rdi        # 6445c0 <pyr_address>
  406f47:	movslq %r12d,%rdx
  406f4a:	cmp    %r15,%rdx
  406f4d:	cmovg  %r15,%rdx
  406f51:	imul   %rbx,%rax
  406f55:	imul   0x20(%rsp),%rbx
  406f5b:	lea    (%rax,%r14,1),%rsi
  406f5f:	add    0x8(%rsp),%rax
  406f64:	imul   %r13,%rsi
  406f68:	imul   %r13,%rax
  406f6c:	lea    (%rsi,%r11,1),%r14
  406f70:	add    %rdx,%rsi
  406f73:	mov    %r14,%r8
  406f76:	mov    %r14,%r12
  406f79:	mov    %r14,0x23d560(%rip)        # 6444e0 <pyr_offset1>
  406f80:	sar    $0x3,%r8
  406f84:	and    $0x7,%r12d
  406f88:	add    %rdi,%r8
  406f8b:	mov    %r12,0x23d61e(%rip)        # 6445b0 <pyr_offset2>
  406f92:	mov    %r12d,%ecx
  406f95:	mov    %r8,0x23d54c(%rip)        # 6444e8 <pyr_address2>
  406f9c:	movzbl (%r8),%ebp
  406fa0:	mov    %rsi,0x23d539(%rip)        # 6444e0 <pyr_offset1>
  406fa7:	sar    %cl,%ebp
  406fa9:	mov    %rsi,%rcx
  406fac:	sar    $0x3,%rsi
  406fb0:	add    %rdi,%rsi
  406fb3:	and    $0x7,%ecx
  406fb6:	mov    %ebp,%r9d
  406fb9:	mov    %rcx,0x23d5f0(%rip)        # 6445b0 <pyr_offset2>
  406fc0:	mov    %rsi,0x23d521(%rip)        # 6444e8 <pyr_address2>
  406fc7:	and    $0x1,%r9d
  406fcb:	movzbl (%rsi),%r10d
  406fcf:	lea    (%rax,%r11,1),%rsi
  406fd3:	add    %rdx,%rax
  406fd6:	mov    %r9w,0x16(%rsp)
  406fdc:	mov    %rsi,0x23d4fd(%rip)        # 6444e0 <pyr_offset1>
  406fe3:	sar    %cl,%r10d
  406fe6:	mov    %rsi,%rcx
  406fe9:	sar    $0x3,%rsi
  406fed:	add    %rdi,%rsi
  406ff0:	and    $0x7,%ecx
  406ff3:	and    $0x1,%r10d
  406ff7:	mov    %rcx,0x23d5b2(%rip)        # 6445b0 <pyr_offset2>
  406ffe:	mov    %rsi,0x23d4e3(%rip)        # 6444e8 <pyr_address2>
  407005:	movzbl (%rsi),%ebp
  407008:	mov    %rax,0x23d4d1(%rip)        # 6444e0 <pyr_offset1>
  40700f:	sar    %cl,%ebp
  407011:	mov    %rax,%rcx
  407014:	sar    $0x3,%rax
  407018:	add    %rdi,%rax
  40701b:	and    $0x7,%ecx
  40701e:	and    $0x1,%ebp
  407021:	mov    %rcx,0x23d588(%rip)        # 6445b0 <pyr_offset2>
  407028:	mov    %rax,0x23d4b9(%rip)        # 6444e8 <pyr_address2>
  40702f:	movzbl (%rax),%r9d
  407033:	mov    (%rsp),%rax
  407037:	lea    (%rbx,%rax,1),%rsi
  40703b:	sar    %cl,%r9d
  40703e:	imul   %r13,%rsi
  407042:	and    $0x1,%r9d
  407046:	lea    (%rsi,%r11,1),%rax
  40704a:	mov    %rax,0x23d48f(%rip)        # 6444e0 <pyr_offset1>
  407051:	mov    %rax,%rcx
  407054:	sar    $0x3,%rax
  407058:	and    $0x7,%ecx
  40705b:	add    %rdi,%rax
  40705e:	mov    %rcx,0x23d54b(%rip)        # 6445b0 <pyr_offset2>
  407065:	mov    %rax,0x23d47c(%rip)        # 6444e8 <pyr_address2>
  40706c:	movzbl (%rax),%eax
  40706f:	sar    %cl,%eax
  407071:	and    $0x1,%eax
  407074:	add    0x8(%rsp),%rbx
  407079:	add    %rdx,%rsi
  40707c:	mov    %rsi,0x23d45d(%rip)        # 6444e0 <pyr_offset1>
  407083:	mov    %rsi,%rcx
  407086:	sar    $0x3,%rsi
  40708a:	and    $0x7,%ecx
  40708d:	add    %rdi,%rsi
  407090:	or     %eax,%ebp
  407092:	mov    %rcx,0x23d517(%rip)        # 6445b0 <pyr_offset2>
  407099:	mov    %rsi,0x23d448(%rip)        # 6444e8 <pyr_address2>
  4070a0:	imul   %rbx,%r13
  4070a4:	movzbl (%rsi),%eax
  4070a7:	add    %r13,%r11
  4070aa:	sar    %cl,%eax
  4070ac:	add    %rdx,%r13
  4070af:	mov    %r11,0x23d42a(%rip)        # 6444e0 <pyr_offset1>
  4070b6:	mov    %r11,%rcx
  4070b9:	sar    $0x3,%r11
  4070bd:	and    $0x7,%ecx
  4070c0:	add    %rdi,%r11
  4070c3:	and    $0x1,%eax
  4070c6:	mov    %rcx,0x23d4e3(%rip)        # 6445b0 <pyr_offset2>
  4070cd:	mov    %r11,0x23d414(%rip)        # 6444e8 <pyr_address2>
  4070d4:	movzbl (%r11),%ebx
  4070d8:	mov    %r13,0x23d401(%rip)        # 6444e0 <pyr_offset1>
  4070df:	sar    %cl,%ebx
  4070e1:	mov    %r13,%rcx
  4070e4:	sar    $0x3,%r13
  4070e8:	and    $0x1,%ebx
  4070eb:	and    $0x7,%ecx
  4070ee:	add    %r13,%rdi
  4070f1:	or     %ebx,%ebp
  4070f3:	mov    %rcx,0x23d4b6(%rip)        # 6445b0 <pyr_offset2>
  4070fa:	mov    %rdi,0x23d3e7(%rip)        # 6444e8 <pyr_address2>
  407101:	or     %ebp,%r10d
  407104:	movzbl (%rdi),%r13d
  407108:	or     0x16(%rsp),%r10w
  40710e:	mov    %r14,0x23d3cb(%rip)        # 6444e0 <pyr_offset1>
  407115:	mov    %r12,0x23d494(%rip)        # 6445b0 <pyr_offset2>
  40711c:	mov    %r8,0x23d3c5(%rip)        # 6444e8 <pyr_address2>
  407123:	sar    %cl,%r13d
  407126:	or     %r10d,%r9d
  407129:	mov    %r12d,%ecx
  40712c:	and    $0x1,%r13d
  407130:	or     %r9d,%eax
  407133:	or     %r13d,%eax
  407136:	shl    %cl,%eax
  407138:	or     %al,(%r8)
  40713b:	movswq 0x23d3bd(%rip),%r13        # 644500 <pyr_len>
  407143:	cmp    %r13,%r15
  407146:	mov    %r13,%rdx
  407149:	jl     406f20 <Or_Neighbors_In_Base+0xe0>
  40714f:	movswq 0x23d3ab(%rip),%rbx        # 644502 <pyr_len+0x2>
  407157:	mov    %rbx,%r15
  40715a:	mov    0x28(%rsp),%r11
  40715f:	mov    %r11,(%rsp)
  407163:	cmp    (%rsp),%rbx
  407167:	jg     406ee0 <Or_Neighbors_In_Base+0xa0>
  40716d:	mov    0x30(%rsp),%rdi
  407172:	cmp    %rdi,0x38(%rsp)
  407177:	je     40718a <Or_Neighbors_In_Base+0x34a>
  407179:	movswl 0x23d384(%rip),%ebp        # 644504 <pyr_len+0x4>
  407180:	mov    %rdi,0x18(%rsp)
  407185:	jmpq   406eb0 <Or_Neighbors_In_Base+0x70>
  40718a:	add    $0x48,%rsp
  40718e:	pop    %rbx
  40718f:	pop    %rbp
  407190:	pop    %r12
  407192:	pop    %r13
  407194:	pop    %r14
  407196:	pop    %r15
  407198:	retq   
  407199:	nopl   0x0(%rax)

00000000004071a0 <Allocate_Pyramid_Level>:
  4071a0:	push   %rbp
  4071a1:	push   %rbx
  4071a2:	mov    %rsi,%rbp
  4071a5:	mov    %rdi,%rbx
  4071a8:	xor    %eax,%eax
  4071aa:	mov    $0x419378,%edi
  4071af:	sub    $0x8,%rsp
  4071b3:	callq  401170 <printf@plt>
  4071b8:	mov    %rbp,%rdi
  4071bb:	callq  401270 <malloc@plt>
  4071c0:	test   %rax,%rax
  4071c3:	mov    %rax,(%rbx)
  4071c6:	je     4072c0 <Allocate_Pyramid_Level+0x120>
  4071cc:	test   %rbp,%rbp
  4071cf:	jle    40729e <Allocate_Pyramid_Level+0xfe>
  4071d5:	mov    %rbp,%rdx
  4071d8:	xor    %ecx,%ecx
  4071da:	and    $0x7,%edx
  4071dd:	je     407252 <Allocate_Pyramid_Level+0xb2>
  4071df:	cmp    $0x1,%rdx
  4071e3:	je     407241 <Allocate_Pyramid_Level+0xa1>
  4071e5:	cmp    $0x2,%rdx
  4071e9:	je     407235 <Allocate_Pyramid_Level+0x95>
  4071eb:	cmp    $0x3,%rdx
  4071ef:	je     407229 <Allocate_Pyramid_Level+0x89>
  4071f1:	cmp    $0x4,%rdx
  4071f5:	je     40721d <Allocate_Pyramid_Level+0x7d>
  4071f7:	cmp    $0x5,%rdx
  4071fb:	je     407212 <Allocate_Pyramid_Level+0x72>
  4071fd:	cmp    $0x6,%rdx
  407201:	jne    4072a8 <Allocate_Pyramid_Level+0x108>
  407207:	mov    (%rbx),%rsi
  40720a:	movb   $0x0,(%rsi,%rcx,1)
  40720e:	add    $0x1,%rcx
  407212:	mov    (%rbx),%rdi
  407215:	movb   $0x0,(%rdi,%rcx,1)
  407219:	add    $0x1,%rcx
  40721d:	mov    (%rbx),%r8
  407220:	movb   $0x0,(%r8,%rcx,1)
  407225:	add    $0x1,%rcx
  407229:	mov    (%rbx),%r9
  40722c:	movb   $0x0,(%r9,%rcx,1)
  407231:	add    $0x1,%rcx
  407235:	mov    (%rbx),%r10
  407238:	movb   $0x0,(%r10,%rcx,1)
  40723d:	add    $0x1,%rcx
  407241:	mov    (%rbx),%r11
  407244:	movb   $0x0,(%r11,%rcx,1)
  407249:	add    $0x1,%rcx
  40724d:	cmp    %rcx,%rbp
  407250:	je     40729e <Allocate_Pyramid_Level+0xfe>
  407252:	mov    (%rbx),%rdx
  407255:	movb   $0x0,(%rdx,%rcx,1)
  407259:	mov    (%rbx),%rax
  40725c:	movb   $0x0,0x1(%rax,%rcx,1)
  407261:	mov    (%rbx),%rsi
  407264:	movb   $0x0,0x2(%rsi,%rcx,1)
  407269:	mov    (%rbx),%rdi
  40726c:	movb   $0x0,0x3(%rdi,%rcx,1)
  407271:	mov    (%rbx),%r8
  407274:	movb   $0x0,0x4(%r8,%rcx,1)
  40727a:	mov    (%rbx),%r9
  40727d:	movb   $0x0,0x5(%r9,%rcx,1)
  407283:	mov    (%rbx),%r10
  407286:	movb   $0x0,0x6(%r10,%rcx,1)
  40728c:	mov    (%rbx),%r11
  40728f:	movb   $0x0,0x7(%r11,%rcx,1)
  407295:	add    $0x8,%rcx
  407299:	cmp    %rcx,%rbp
  40729c:	jne    407252 <Allocate_Pyramid_Level+0xb2>
  40729e:	add    $0x8,%rsp
  4072a2:	pop    %rbx
  4072a3:	pop    %rbp
  4072a4:	retq   
  4072a5:	nopl   (%rax)
  4072a8:	mov    (%rbx),%rax
  4072ab:	mov    $0x1,%ecx
  4072b0:	movb   $0x0,(%rax)
  4072b3:	jmpq   407207 <Allocate_Pyramid_Level+0x67>
  4072b8:	nopl   0x0(%rax,%rax,1)
  4072c0:	mov    $0x4193a8,%edi
  4072c5:	callq  403650 <Error>
  4072ca:	jmpq   4071cc <Allocate_Pyramid_Level+0x2c>
  4072cf:	nop

00000000004072d0 <Compute_Pyramid_Level>:
  4072d0:	push   %r15
  4072d2:	push   %r14
  4072d4:	lea    -0x1(%rdi),%r15
  4072d8:	push   %r13
  4072da:	push   %r12
  4072dc:	mov    %rdi,%rsi
  4072df:	push   %rbp
  4072e0:	push   %rbx
  4072e1:	xor    %eax,%eax
  4072e3:	mov    %rdi,%rbx
  4072e6:	mov    %r15,%rdx
  4072e9:	sub    $0x68,%rsp
  4072ed:	mov    %rdi,0x50(%rsp)
  4072f2:	mov    $0x4193d8,%edi
  4072f7:	mov    %r15,0x48(%rsp)
  4072fc:	callq  401170 <printf@plt>
  407301:	lea    (%rbx,%rbx,2),%rax
  407305:	add    %rax,%rax
  407308:	movzwl 0x644504(%rax),%r10d
  407310:	test   %r10w,%r10w
  407314:	jle    407688 <Compute_Pyramid_Level+0x3b8>
  40731a:	lea    (%r15,%r15,2),%rcx
  40731e:	movzwl 0x644502(%rax),%r12d
  407326:	movq   $0x0,0x30(%rsp)
  40732f:	mov    %rax,0x58(%rsp)
  407334:	lea    0x644500(%rcx,%rcx,1),%r15
  40733c:	nopl   0x0(%rax)
  407340:	mov    0x30(%rsp),%rdi
  407345:	movswl 0x4(%r15),%eax
  40734a:	lea    (%rdi,%rdi,1),%rbp
  40734e:	sub    $0x1,%eax
  407351:	lea    0x1(%rbp),%r8
  407355:	cltq   
  407357:	mov    %rbp,0x40(%rsp)
  40735c:	cmp    %r8,%rax
  40735f:	cmovle %rax,%r8
  407363:	test   %r12w,%r12w
  407367:	mov    %r8,0x38(%rsp)
  40736c:	jle    407670 <Compute_Pyramid_Level+0x3a0>
  407372:	mov    0x58(%rsp),%rsi
  407377:	movq   $0x0,0x28(%rsp)
  407380:	movswq %r12w,%r9
  407384:	mov    0x28(%rsp),%r11
  407389:	mov    %r9,0x8(%rsp)
  40738e:	movswq 0x644500(%rsi),%rbp
  407396:	add    $0x644500,%rsi
  40739d:	mov    %rsi,0x20(%rsp)
  4073a2:	nopw   0x0(%rax,%rax,1)
  4073a8:	movswq 0x2(%r15),%rax
  4073ad:	lea    (%r11,%r11,1),%r10
  4073b1:	lea    0x1(%r10),%r11
  4073b5:	mov    %r10,0x18(%rsp)
  4073ba:	mov    %rax,%rbx
  4073bd:	sub    $0x1,%eax
  4073c0:	cltq   
  4073c2:	cmp    %r11,%rax
  4073c5:	cmovle %rax,%r11
  4073c9:	test   %rbp,%rbp
  4073cc:	mov    %r11,0x10(%rsp)
  4073d1:	jle    40764d <Compute_Pyramid_Level+0x37d>
  4073d7:	xor    %r14d,%r14d
  4073da:	jmp    4073ef <Compute_Pyramid_Level+0x11f>
  4073dc:	nopl   0x0(%rax)
  4073e0:	movswq 0x2(%rdi),%rdx
  4073e5:	movswq 0x2(%r15),%rbx
  4073ea:	mov    %rdx,0x8(%rsp)
  4073ef:	movswq (%r15),%r12
  4073f3:	lea    (%r14,%r14,1),%rdx
  4073f7:	mov    0x40(%rsp),%rax
  4073fc:	mov    0x18(%rsp),%rcx
  407401:	mov    0x48(%rsp),%rdi
  407406:	lea    0x1(%rdx),%r13
  40740a:	mov    %r12,%r9
  40740d:	sub    $0x1,%r12d
  407411:	mov    0x6445c0(,%rdi,8),%rdi
  407419:	movslq %r12d,%r8
  40741c:	cmp    %r13,%r8
  40741f:	cmovg  %r13,%r8
  407423:	imul   %rbx,%rax
  407427:	imul   0x38(%rsp),%rbx
  40742d:	lea    (%rax,%rcx,1),%rsi
  407431:	add    0x10(%rsp),%rax
  407436:	imul   %r9,%rsi
  40743a:	imul   %r9,%rax
  40743e:	lea    (%rsi,%rdx,1),%r10
  407442:	add    %r8,%rsi
  407445:	mov    %r10,0x23d094(%rip)        # 6444e0 <pyr_offset1>
  40744c:	mov    %r10,%rcx
  40744f:	sar    $0x3,%r10
  407453:	add    %rdi,%r10
  407456:	and    $0x7,%ecx
  407459:	lea    (%rax,%rdx,1),%r13
  40745d:	mov    %rcx,0x23d14c(%rip)        # 6445b0 <pyr_offset2>
  407464:	mov    %r10,0x23d07d(%rip)        # 6444e8 <pyr_address2>
  40746b:	add    %r8,%rax
  40746e:	movzbl (%r10),%r12d
  407472:	mov    %rsi,0x23d067(%rip)        # 6444e0 <pyr_offset1>
  407479:	sar    %cl,%r12d
  40747c:	mov    %rsi,%rcx
  40747f:	sar    $0x3,%rsi
  407483:	add    %rdi,%rsi
  407486:	and    $0x7,%ecx
  407489:	and    $0x1,%r12d
  40748d:	mov    %rcx,0x23d11c(%rip)        # 6445b0 <pyr_offset2>
  407494:	mov    %rsi,0x23d04d(%rip)        # 6444e8 <pyr_address2>
  40749b:	movzbl (%rsi),%r11d
  40749f:	mov    %r13,0x23d03a(%rip)        # 6444e0 <pyr_offset1>
  4074a6:	sar    %cl,%r11d
  4074a9:	mov    %r13,%rcx
  4074ac:	sar    $0x3,%r13
  4074b0:	and    $0x7,%ecx
  4074b3:	add    %rdi,%r13
  4074b6:	and    $0x1,%r11d
  4074ba:	mov    %rcx,0x23d0ef(%rip)        # 6445b0 <pyr_offset2>
  4074c1:	mov    %r13,0x23d020(%rip)        # 6444e8 <pyr_address2>
  4074c8:	movzbl 0x0(%r13),%r13d
  4074cd:	mov    %rax,0x23d00c(%rip)        # 6444e0 <pyr_offset1>
  4074d4:	sar    %cl,%r13d
  4074d7:	mov    %rax,%rcx
  4074da:	sar    $0x3,%rax
  4074de:	add    %rdi,%rax
  4074e1:	and    $0x7,%ecx
  4074e4:	and    $0x1,%r13d
  4074e8:	mov    %rcx,0x23d0c1(%rip)        # 6445b0 <pyr_offset2>
  4074ef:	mov    %rax,0x23cff2(%rip)        # 6444e8 <pyr_address2>
  4074f6:	movzbl (%rax),%r10d
  4074fa:	mov    0x18(%rsp),%rax
  4074ff:	lea    (%rbx,%rax,1),%rsi
  407503:	sar    %cl,%r10d
  407506:	imul   %r9,%rsi
  40750a:	and    $0x1,%r10d
  40750e:	lea    (%rsi,%rdx,1),%rax
  407512:	mov    %rax,0x23cfc7(%rip)        # 6444e0 <pyr_offset1>
  407519:	mov    %rax,%rcx
  40751c:	sar    $0x3,%rax
  407520:	and    $0x7,%ecx
  407523:	add    %rdi,%rax
  407526:	mov    %rcx,0x23d083(%rip)        # 6445b0 <pyr_offset2>
  40752d:	mov    %rax,0x23cfb4(%rip)        # 6444e8 <pyr_address2>
  407534:	movzbl (%rax),%eax
  407537:	sar    %cl,%eax
  407539:	and    $0x1,%eax
  40753c:	add    %r8,%rsi
  40753f:	mov    %rsi,0x23cf9a(%rip)        # 6444e0 <pyr_offset1>
  407546:	mov    %rsi,%rcx
  407549:	sar    $0x3,%rsi
  40754d:	and    $0x7,%ecx
  407550:	add    %rdi,%rsi
  407553:	or     %eax,%r13d
  407556:	mov    %rcx,0x23d053(%rip)        # 6445b0 <pyr_offset2>
  40755d:	mov    %rsi,0x23cf84(%rip)        # 6444e8 <pyr_address2>
  407564:	movzbl (%rsi),%esi
  407567:	add    0x10(%rsp),%rbx
  40756c:	imul   %rbx,%r9
  407570:	sar    %cl,%esi
  407572:	and    $0x1,%esi
  407575:	add    %r9,%rdx
  407578:	add    %r8,%r9
  40757b:	mov    0x50(%rsp),%r8
  407580:	mov    %rdx,0x23cf59(%rip)        # 6444e0 <pyr_offset1>
  407587:	mov    %rdx,%rcx
  40758a:	sar    $0x3,%rdx
  40758e:	add    %rdi,%rdx
  407591:	and    $0x7,%ecx
  407594:	mov    %rcx,0x23d015(%rip)        # 6445b0 <pyr_offset2>
  40759b:	mov    %rdx,0x23cf46(%rip)        # 6444e8 <pyr_address2>
  4075a2:	movzbl (%rdx),%ebx
  4075a5:	mov    %r9,0x23cf34(%rip)        # 6444e0 <pyr_offset1>
  4075ac:	sar    %cl,%ebx
  4075ae:	mov    %r9,%rcx
  4075b1:	sar    $0x3,%r9
  4075b5:	add    %rdi,%r9
  4075b8:	and    $0x7,%ecx
  4075bb:	and    $0x1,%ebx
  4075be:	mov    %rcx,0x23cfeb(%rip)        # 6445b0 <pyr_offset2>
  4075c5:	mov    %r9,0x23cf1c(%rip)        # 6444e8 <pyr_address2>
  4075cc:	or     %ebx,%r13d
  4075cf:	movzbl (%r9),%edx
  4075d3:	mov    0x8(%rsp),%r9
  4075d8:	or     %r13d,%r12d
  4075db:	imul   0x30(%rsp),%r9
  4075e1:	or     %r12d,%r11d
  4075e4:	mov    0x20(%rsp),%rdi
  4075e9:	or     %r11d,%r10d
  4075ec:	sar    %cl,%edx
  4075ee:	or     %r10d,%esi
  4075f1:	add    0x28(%rsp),%r9
  4075f6:	and    $0x1,%edx
  4075f9:	or     %edx,%esi
  4075fb:	imul   %r9,%rbp
  4075ff:	add    %r14,%rbp
  407602:	mov    %rbp,%rcx
  407605:	mov    %rbp,0x23ced4(%rip)        # 6444e0 <pyr_offset1>
  40760c:	and    $0x7,%ecx
  40760f:	sar    $0x3,%rbp
  407613:	add    0x6445c0(,%r8,8),%rbp
  40761b:	shl    %cl,%esi
  40761d:	mov    %rcx,0x23cf8c(%rip)        # 6445b0 <pyr_offset2>
  407624:	add    $0x1,%r14
  407628:	mov    %rbp,0x23ceb9(%rip)        # 6444e8 <pyr_address2>
  40762f:	or     %sil,0x0(%rbp)
  407633:	movswq (%rdi),%rbp
  407637:	cmp    %r14,%rbp
  40763a:	jg     4073e0 <Compute_Pyramid_Level+0x110>
  407640:	movswq 0x2(%rdi),%r14
  407645:	mov    %r14,%r12
  407648:	mov    %r14,0x8(%rsp)
  40764d:	addq   $0x1,0x28(%rsp)
  407653:	mov    0x28(%rsp),%r11
  407658:	cmp    %r11,0x8(%rsp)
  40765d:	jg     4073a8 <Compute_Pyramid_Level+0xd8>
  407663:	mov    0x58(%rsp),%r13
  407668:	movzwl 0x644504(%r13),%r10d
  407670:	addq   $0x1,0x30(%rsp)
  407676:	movswq %r10w,%rax
  40767a:	mov    0x30(%rsp),%rsi
  40767f:	cmp    %rsi,%rax
  407682:	jg     407340 <Compute_Pyramid_Level+0x70>
  407688:	add    $0x68,%rsp
  40768c:	pop    %rbx
  40768d:	pop    %rbp
  40768e:	pop    %r12
  407690:	pop    %r13
  407692:	pop    %r14
  407694:	pop    %r15
  407696:	retq   
  407697:	nopw   0x0(%rax,%rax,1)

00000000004076a0 <Compute_Octree>:
  4076a0:	movswq 0x23cf68(%rip),%rdi        # 644610 <opc_len>
  4076a8:	movswq 0x23cf62(%rip),%rax        # 644612 <opc_len+0x2>
  4076b0:	mov    $0x0,%edx
  4076b5:	push   %r14
  4076b7:	push   %r13
  4076b9:	mov    $0x1,%ecx
  4076be:	push   %r12
  4076c0:	push   %rbp
  4076c1:	push   %rbx
  4076c2:	movswq 0x23cf4a(%rip),%rbx        # 644614 <opc_len+0x4>
  4076ca:	cmp    %rax,%rdi
  4076cd:	mov    %cx,0x23ced4(%rip)        # 6445a8 <pyr_levels>
  4076d4:	cmovl  %rax,%rdi
  4076d8:	test   %rdi,%rdi
  4076db:	cmovns %rdi,%rdx
  4076df:	cmp    %rdx,%rbx
  4076e2:	cmovl  %rdx,%rbx
  4076e6:	cmp    $0x1,%rbx
  4076ea:	jle    407bc0 <Compute_Octree+0x520>
  4076f0:	mov    $0x2,%ebp
  4076f5:	mov    $0x1,%r9d
  4076fb:	nopl   0x0(%rax,%rax,1)
  407700:	movswl %bp,%esi
  407703:	mov    %r9d,%r10d
  407706:	mov    %ebp,%r8d
  407709:	lea    -0x1(%rsi),%ecx
  40770c:	add    $0x1,%ebp
  40770f:	shl    %cl,%r10d
  407712:	movslq %r10d,%r11
  407715:	cmp    %rbx,%r11
  407718:	jl     407700 <Compute_Octree+0x60>
  40771a:	mov    %r8w,0x23ce86(%rip)        # 6445a8 <pyr_levels>
  407722:	mov    $0x419410,%edi
  407727:	xor    %eax,%eax
  407729:	callq  401170 <printf@plt>
  40772e:	movzwl 0x23cedc(%rip),%r13d        # 644612 <opc_len+0x2>
  407736:	movswl 0x23ced2(%rip),%r12d        # 644610 <opc_len>
  40773e:	mov    $0x1,%edi
  407743:	movswl 0x23cec9(%rip),%r14d        # 644614 <opc_len+0x4>
  40774b:	mov    %di,0x23cdf2(%rip)        # 644544 <pyr_voxlen+0x4>
  407752:	mov    $0x419378,%edi
  407757:	movl   $0x10001,0x23cddf(%rip)        # 644540 <pyr_voxlen>
  407761:	movswl %r13w,%eax
  407765:	mov    %r12w,0x23cd93(%rip)        # 644500 <pyr_len>
  40776d:	mov    %r13w,0x23cd8d(%rip)        # 644502 <pyr_len+0x2>
  407775:	imul   %eax,%r12d
  407779:	mov    %r14w,0x23cd83(%rip)        # 644504 <pyr_len+0x4>
  407781:	imul   %r14d,%r12d
  407785:	lea    0xe(%r12),%ebx
  40778a:	add    $0x7,%r12d
  40778e:	cmovns %r12d,%ebx
  407792:	xor    %eax,%eax
  407794:	sar    $0x3,%ebx
  407797:	movslq %ebx,%rbp
  40779a:	mov    %ebx,0x23cde0(%rip)        # 644580 <pyr_length>
  4077a0:	mov    %rbp,%rsi
  4077a3:	callq  401170 <printf@plt>
  4077a8:	mov    %rbp,%rdi
  4077ab:	callq  401270 <malloc@plt>
  4077b0:	test   %rax,%rax
  4077b3:	mov    %rax,0x23ce06(%rip)        # 6445c0 <pyr_address>
  4077ba:	je     407bb0 <Compute_Octree+0x510>
  4077c0:	test   %ebx,%ebx
  4077c2:	jle    4078d5 <Compute_Octree+0x235>
  4077c8:	mov    %rbp,%rdx
  4077cb:	xor    %r8d,%r8d
  4077ce:	and    $0x7,%edx
  4077d1:	je     407865 <Compute_Octree+0x1c5>
  4077d7:	cmp    $0x1,%rdx
  4077db:	je     40784f <Compute_Octree+0x1af>
  4077dd:	cmp    $0x2,%rdx
  4077e1:	je     40783f <Compute_Octree+0x19f>
  4077e3:	cmp    $0x3,%rdx
  4077e7:	je     40782f <Compute_Octree+0x18f>
  4077e9:	cmp    $0x4,%rdx
  4077ed:	je     40781f <Compute_Octree+0x17f>
  4077ef:	cmp    $0x5,%rdx
  4077f3:	je     40780f <Compute_Octree+0x16f>
  4077f5:	cmp    $0x6,%rdx
  4077f9:	jne    407b98 <Compute_Octree+0x4f8>
  4077ff:	mov    0x23cdba(%rip),%rcx        # 6445c0 <pyr_address>
  407806:	movb   $0x0,(%rcx,%r8,1)
  40780b:	add    $0x1,%r8
  40780f:	mov    0x23cdaa(%rip),%r10        # 6445c0 <pyr_address>
  407816:	movb   $0x0,(%r10,%r8,1)
  40781b:	add    $0x1,%r8
  40781f:	mov    0x23cd9a(%rip),%r11        # 6445c0 <pyr_address>
  407826:	movb   $0x0,(%r11,%r8,1)
  40782b:	add    $0x1,%r8
  40782f:	mov    0x23cd8a(%rip),%r12        # 6445c0 <pyr_address>
  407836:	movb   $0x0,(%r12,%r8,1)
  40783b:	add    $0x1,%r8
  40783f:	mov    0x23cd7a(%rip),%rsi        # 6445c0 <pyr_address>
  407846:	movb   $0x0,(%rsi,%r8,1)
  40784b:	add    $0x1,%r8
  40784f:	mov    0x23cd6a(%rip),%r13        # 6445c0 <pyr_address>
  407856:	movb   $0x0,0x0(%r13,%r8,1)
  40785c:	add    $0x1,%r8
  407860:	cmp    %r8,%rbp
  407863:	je     4078d5 <Compute_Octree+0x235>
  407865:	mov    0x23cd54(%rip),%r14        # 6445c0 <pyr_address>
  40786c:	movb   $0x0,(%r14,%r8,1)
  407871:	mov    0x23cd48(%rip),%rdi        # 6445c0 <pyr_address>
  407878:	movb   $0x0,0x1(%rdi,%r8,1)
  40787e:	mov    0x23cd3b(%rip),%rax        # 6445c0 <pyr_address>
  407885:	movb   $0x0,0x2(%rax,%r8,1)
  40788b:	mov    0x23cd2e(%rip),%rbx        # 6445c0 <pyr_address>
  407892:	movb   $0x0,0x3(%rbx,%r8,1)
  407898:	mov    0x23cd21(%rip),%rdx        # 6445c0 <pyr_address>
  40789f:	movb   $0x0,0x4(%rdx,%r8,1)
  4078a5:	mov    0x23cd14(%rip),%r9        # 6445c0 <pyr_address>
  4078ac:	movb   $0x0,0x5(%r9,%r8,1)
  4078b2:	mov    0x23cd07(%rip),%rcx        # 6445c0 <pyr_address>
  4078b9:	movb   $0x0,0x6(%rcx,%r8,1)
  4078bf:	mov    0x23ccfa(%rip),%r10        # 6445c0 <pyr_address>
  4078c6:	movb   $0x0,0x7(%r10,%r8,1)
  4078cc:	add    $0x8,%r8
  4078d0:	cmp    %r8,%rbp
  4078d3:	jne    407865 <Compute_Octree+0x1c5>
  4078d5:	mov    $0x41956b,%edi
  4078da:	callq  401110 <puts@plt>
  4078df:	mov    0x23a9f2(%rip),%rbp        # 6422d8 <Global>
  4078e6:	movq   $0x0,0x0(%rbp)
  4078ee:	callq  406bb0 <Compute_Base>
  4078f3:	mov    $0x419440,%edi
  4078f8:	callq  401110 <puts@plt>
  4078fd:	mov    0x23a9d4(%rip),%r8        # 6422d8 <Global>
  407904:	movq   $0x0,(%r8)
  40790b:	callq  406e40 <Or_Neighbors_In_Base>
  407910:	cmpw   $0x1,0x23cc90(%rip)        # 6445a8 <pyr_levels>
  407918:	jle    407b50 <Compute_Octree+0x4b0>
  40791e:	mov    $0x644500,%r12d
  407924:	mov    $0x644540,%ebp
  407929:	mov    $0x1,%ebx
  40792e:	xchg   %ax,%ax
  407930:	movswl (%r12),%eax
  407935:	movzwl 0x0(%rbp),%r11d
  40793a:	cmp    $0x1,%ax
  40793e:	jle    407948 <Compute_Octree+0x2a8>
  407940:	add    $0x1,%eax
  407943:	add    %r11d,%r11d
  407946:	sar    %eax
  407948:	movswl 0x2(%r12),%r13d
  40794e:	mov    %r11w,0x6(%rbp)
  407953:	mov    %ax,0x6(%r12)
  407959:	cmp    $0x1,%r13w
  40795e:	jle    407b70 <Compute_Octree+0x4d0>
  407964:	movswl 0x2(%rbp),%esi
  407968:	add    $0x1,%r13d
  40796c:	sar    %r13d
  40796f:	add    %esi,%esi
  407971:	movswl 0x4(%r12),%r14d
  407977:	mov    %si,0x8(%rbp)
  40797b:	mov    %r13w,0x8(%r12)
  407981:	cmp    $0x1,%r14w
  407986:	jle    407b60 <Compute_Octree+0x4c0>
  40798c:	movswl 0x4(%rbp),%edi
  407990:	add    $0x1,%r14d
  407994:	sar    %r14d
  407997:	add    %edi,%edi
  407999:	movswl %r13w,%edx
  40799d:	cwtl   
  40799e:	movswl %r14w,%r9d
  4079a2:	imul   %edx,%eax
  4079a5:	mov    %r14w,0xa(%r12)
  4079ab:	mov    %di,0xa(%rbp)
  4079af:	mov    $0x419378,%edi
  4079b4:	imul   %r9d,%eax
  4079b8:	lea    0xe(%rax),%r13d
  4079bc:	add    $0x7,%eax
  4079bf:	cmovns %eax,%r13d
  4079c3:	xor    %eax,%eax
  4079c5:	sar    $0x3,%r13d
  4079c9:	movslq %r13d,%r14
  4079cc:	mov    %r13d,0x644580(,%rbx,4)
  4079d4:	mov    %r14,%rsi
  4079d7:	callq  401170 <printf@plt>
  4079dc:	mov    %r14,%rdi
  4079df:	callq  401270 <malloc@plt>
  4079e4:	test   %rax,%rax
  4079e7:	mov    %rax,0x6445c0(,%rbx,8)
  4079ef:	je     407b80 <Compute_Octree+0x4e0>
  4079f5:	test   %r13d,%r13d
  4079f8:	jle    407b2b <Compute_Octree+0x48b>
  4079fe:	mov    %r14,%rcx
  407a01:	xor    %r8d,%r8d
  407a04:	and    $0x7,%ecx
  407a07:	je     407ab2 <Compute_Octree+0x412>
  407a0d:	cmp    $0x1,%rcx
  407a11:	je     407a9c <Compute_Octree+0x3fc>
  407a17:	cmp    $0x2,%rcx
  407a1b:	je     407a8b <Compute_Octree+0x3eb>
  407a1d:	cmp    $0x3,%rcx
  407a21:	je     407a7a <Compute_Octree+0x3da>
  407a23:	cmp    $0x4,%rcx
  407a27:	je     407a69 <Compute_Octree+0x3c9>
  407a29:	cmp    $0x5,%rcx
  407a2d:	je     407a58 <Compute_Octree+0x3b8>
  407a2f:	cmp    $0x6,%rcx
  407a33:	je     407a47 <Compute_Octree+0x3a7>
  407a35:	mov    0x6445c0(,%rbx,8),%r10
  407a3d:	mov    $0x1,%r8d
  407a43:	movb   $0x0,(%r10)
  407a47:	mov    0x6445c0(,%rbx,8),%rax
  407a4f:	movb   $0x0,(%rax,%r8,1)
  407a54:	add    $0x1,%r8
  407a58:	mov    0x6445c0(,%rbx,8),%r11
  407a60:	movb   $0x0,(%r11,%r8,1)
  407a65:	add    $0x1,%r8
  407a69:	mov    0x6445c0(,%rbx,8),%rsi
  407a71:	movb   $0x0,(%rsi,%r8,1)
  407a76:	add    $0x1,%r8
  407a7a:	mov    0x6445c0(,%rbx,8),%rdi
  407a82:	movb   $0x0,(%rdi,%r8,1)
  407a87:	add    $0x1,%r8
  407a8b:	mov    0x6445c0(,%rbx,8),%rdx
  407a93:	movb   $0x0,(%rdx,%r8,1)
  407a98:	add    $0x1,%r8
  407a9c:	mov    0x6445c0(,%rbx,8),%r9
  407aa4:	movb   $0x0,(%r9,%r8,1)
  407aa9:	add    $0x1,%r8
  407aad:	cmp    %r8,%r14
  407ab0:	je     407b2b <Compute_Octree+0x48b>
  407ab2:	mov    0x6445c0(,%rbx,8),%r13
  407aba:	movb   $0x0,0x0(%r13,%r8,1)
  407ac0:	mov    0x6445c0(,%rbx,8),%rcx
  407ac8:	movb   $0x0,0x1(%rcx,%r8,1)
  407ace:	mov    0x6445c0(,%rbx,8),%r10
  407ad6:	movb   $0x0,0x2(%r10,%r8,1)
  407adc:	mov    0x6445c0(,%rbx,8),%rax
  407ae4:	movb   $0x0,0x3(%rax,%r8,1)
  407aea:	mov    0x6445c0(,%rbx,8),%r11
  407af2:	movb   $0x0,0x4(%r11,%r8,1)
  407af8:	mov    0x6445c0(,%rbx,8),%rsi
  407b00:	movb   $0x0,0x5(%rsi,%r8,1)
  407b06:	mov    0x6445c0(,%rbx,8),%rdi
  407b0e:	movb   $0x0,0x6(%rdi,%r8,1)
  407b14:	mov    0x6445c0(,%rbx,8),%rdx
  407b1c:	movb   $0x0,0x7(%rdx,%r8,1)
  407b22:	add    $0x8,%r8
  407b26:	cmp    %r8,%r14
  407b29:	jne    407ab2 <Compute_Octree+0x412>
  407b2b:	mov    %rbx,%rdi
  407b2e:	add    $0x1,%rbx
  407b32:	add    $0x6,%r12
  407b36:	callq  4072d0 <Compute_Pyramid_Level>
  407b3b:	movswq 0x23ca65(%rip),%r14        # 6445a8 <pyr_levels>
  407b43:	add    $0x6,%rbp
  407b47:	cmp    %rbx,%r14
  407b4a:	jg     407930 <Compute_Octree+0x290>
  407b50:	pop    %rbx
  407b51:	pop    %rbp
  407b52:	pop    %r12
  407b54:	pop    %r13
  407b56:	pop    %r14
  407b58:	retq   
  407b59:	nopl   0x0(%rax)
  407b60:	movzwl 0x4(%rbp),%edi
  407b64:	jmpq   407999 <Compute_Octree+0x2f9>
  407b69:	nopl   0x0(%rax)
  407b70:	movzwl 0x2(%rbp),%esi
  407b74:	jmpq   407971 <Compute_Octree+0x2d1>
  407b79:	nopl   0x0(%rax)
  407b80:	mov    $0x4193a8,%edi
  407b85:	xor    %eax,%eax
  407b87:	callq  403650 <Error>
  407b8c:	jmpq   4079f5 <Compute_Octree+0x355>
  407b91:	nopl   0x0(%rax)
  407b98:	mov    0x23ca21(%rip),%r9        # 6445c0 <pyr_address>
  407b9f:	mov    $0x1,%r8d
  407ba5:	movb   $0x0,(%r9)
  407ba9:	jmpq   4077ff <Compute_Octree+0x15f>
  407bae:	xchg   %ax,%ax
  407bb0:	mov    $0x4193a8,%edi
  407bb5:	callq  403650 <Error>
  407bba:	jmpq   4077c0 <Compute_Octree+0x120>
  407bbf:	nop
  407bc0:	mov    $0x1,%esi
  407bc5:	jmpq   407722 <Compute_Octree+0x82>
  407bca:	nopw   0x0(%rax,%rax,1)

0000000000407bd0 <Load_Octree>:
  407bd0:	push   %r13
  407bd2:	push   %r12
  407bd4:	mov    %rdi,%rsi
  407bd7:	push   %rbp
  407bd8:	push   %rbx
  407bd9:	sub    $0xd8,%rsp
  407be0:	mov    %rsp,%rdi
  407be3:	callq  401140 <stpcpy@plt>
  407be8:	mov    %rsp,%rdi
  407beb:	movl   $0x7279702e,(%rax)
  407bf1:	movb   $0x0,0x4(%rax)
  407bf5:	callq  403180 <Open_File>
  407bfa:	mov    $0x2,%edx
  407bff:	mov    %eax,%edi
  407c01:	mov    $0x64453c,%esi
  407c06:	mov    %eax,%r13d
  407c09:	callq  403480 <Read_Shorts>
  407c0e:	movzwl 0x23c927(%rip),%eax        # 64453c <pyr_version>
  407c15:	cmp    $0x1,%ax
  407c19:	je     407c2a <Load_Octree+0x5a>
  407c1b:	movswl %ax,%esi
  407c1e:	mov    $0x419478,%edi
  407c23:	xor    %eax,%eax
  407c25:	callq  403650 <Error>
  407c2a:	mov    $0x2,%edx
  407c2f:	mov    $0x6445a8,%esi
  407c34:	mov    %r13d,%edi
  407c37:	callq  403480 <Read_Shorts>
  407c3c:	movswl 0x23c965(%rip),%edx        # 6445a8 <pyr_levels>
  407c43:	mov    $0x644500,%esi
  407c48:	mov    %r13d,%edi
  407c4b:	lea    (%rdx,%rdx,2),%ecx
  407c4e:	movslq %ecx,%rdx
  407c51:	shl    $0x3,%rdx
  407c55:	callq  403480 <Read_Shorts>
  407c5a:	movswl 0x23c947(%rip),%ebx        # 6445a8 <pyr_levels>
  407c61:	mov    %r13d,%edi
  407c64:	lea    (%rbx,%rbx,2),%esi
  407c67:	movslq %esi,%rdx
  407c6a:	mov    $0x644540,%esi
  407c6f:	shl    $0x3,%rdx
  407c73:	callq  403480 <Read_Shorts>
  407c78:	movswq 0x23c928(%rip),%rdx        # 6445a8 <pyr_levels>
  407c80:	mov    $0x644580,%esi
  407c85:	mov    %r13d,%edi
  407c88:	shl    $0x2,%rdx
  407c8c:	callq  403530 <Read_Longs>
  407c91:	movswl 0x23c910(%rip),%esi        # 6445a8 <pyr_levels>
  407c98:	xor    %eax,%eax
  407c9a:	mov    $0x4194a0,%edi
  407c9f:	callq  401170 <printf@plt>
  407ca4:	cmpw   $0x0,0x23c8fc(%rip)        # 6445a8 <pyr_levels>
  407cac:	jle    407e08 <Load_Octree+0x238>
  407cb2:	mov    $0x6445c0,%ebx
  407cb7:	xor    %r12d,%r12d
  407cba:	nopw   0x0(%rax,%rax,1)
  407cc0:	movslq 0x644580(,%r12,4),%rbp
  407cc8:	mov    $0x419378,%edi
  407ccd:	xor    %eax,%eax
  407ccf:	mov    %rbp,%rsi
  407cd2:	callq  401170 <printf@plt>
  407cd7:	mov    %rbp,%rdi
  407cda:	callq  401270 <malloc@plt>
  407cdf:	test   %rax,%rax
  407ce2:	mov    %rax,(%rbx)
  407ce5:	je     407e20 <Load_Octree+0x250>
  407ceb:	test   %rbp,%rbp
  407cee:	jle    407dcd <Load_Octree+0x1fd>
  407cf4:	mov    %rbp,%rdi
  407cf7:	xor    %r9d,%r9d
  407cfa:	and    $0x7,%edi
  407cfd:	je     407d7d <Load_Octree+0x1ad>
  407cff:	cmp    $0x1,%rdi
  407d03:	je     407d6c <Load_Octree+0x19c>
  407d05:	cmp    $0x2,%rdi
  407d09:	je     407d60 <Load_Octree+0x190>
  407d0b:	cmp    $0x3,%rdi
  407d0f:	je     407d54 <Load_Octree+0x184>
  407d11:	cmp    $0x4,%rdi
  407d15:	je     407d48 <Load_Octree+0x178>
  407d17:	cmp    $0x5,%rdi
  407d1b:	je     407d3c <Load_Octree+0x16c>
  407d1d:	cmp    $0x6,%rdi
  407d21:	je     407d30 <Load_Octree+0x160>
  407d23:	mov    (%rbx),%r8
  407d26:	mov    $0x1,%r9d
  407d2c:	movb   $0x0,(%r8)
  407d30:	mov    (%rbx),%r10
  407d33:	movb   $0x0,(%r10,%r9,1)
  407d38:	add    $0x1,%r9
  407d3c:	mov    (%rbx),%r11
  407d3f:	movb   $0x0,(%r11,%r9,1)
  407d44:	add    $0x1,%r9
  407d48:	mov    (%rbx),%rax
  407d4b:	movb   $0x0,(%rax,%r9,1)
  407d50:	add    $0x1,%r9
  407d54:	mov    (%rbx),%rdx
  407d57:	movb   $0x0,(%rdx,%r9,1)
  407d5c:	add    $0x1,%r9
  407d60:	mov    (%rbx),%rcx
  407d63:	movb   $0x0,(%rcx,%r9,1)
  407d68:	add    $0x1,%r9
  407d6c:	mov    (%rbx),%rsi
  407d6f:	movb   $0x0,(%rsi,%r9,1)
  407d74:	add    $0x1,%r9
  407d78:	cmp    %r9,%rbp
  407d7b:	je     407dcd <Load_Octree+0x1fd>
  407d7d:	mov    (%rbx),%rdi
  407d80:	movb   $0x0,(%rdi,%r9,1)
  407d85:	mov    (%rbx),%r8
  407d88:	movb   $0x0,0x1(%r8,%r9,1)
  407d8e:	mov    (%rbx),%r10
  407d91:	movb   $0x0,0x2(%r10,%r9,1)
  407d97:	mov    (%rbx),%r11
  407d9a:	movb   $0x0,0x3(%r11,%r9,1)
  407da0:	mov    (%rbx),%rax
  407da3:	movb   $0x0,0x4(%rax,%r9,1)
  407da9:	mov    (%rbx),%rdx
  407dac:	movb   $0x0,0x5(%rdx,%r9,1)
  407db2:	mov    (%rbx),%rcx
  407db5:	movb   $0x0,0x6(%rcx,%r9,1)
  407dbb:	mov    (%rbx),%rsi
  407dbe:	movb   $0x0,0x7(%rsi,%r9,1)
  407dc4:	add    $0x8,%r9
  407dc8:	cmp    %r9,%rbp
  407dcb:	jne    407d7d <Load_Octree+0x1ad>
  407dcd:	mov    %r12,%rsi
  407dd0:	mov    $0x4194d0,%edi
  407dd5:	xor    %eax,%eax
  407dd7:	callq  401170 <printf@plt>
  407ddc:	movslq 0x644580(,%r12,4),%rdx
  407de4:	mov    (%rbx),%rsi
  407de7:	mov    %r13d,%edi
  407dea:	add    $0x1,%r12
  407dee:	add    $0x8,%rbx
  407df2:	callq  4033d0 <Read_Bytes>
  407df7:	movswq 0x23c7a9(%rip),%rbp        # 6445a8 <pyr_levels>
  407dff:	cmp    %r12,%rbp
  407e02:	jg     407cc0 <Load_Octree+0xf0>
  407e08:	mov    %r13d,%edi
  407e0b:	callq  4035e0 <Close_File>
  407e10:	add    $0xd8,%rsp
  407e17:	pop    %rbx
  407e18:	pop    %rbp
  407e19:	pop    %r12
  407e1b:	pop    %r13
  407e1d:	retq   
  407e1e:	xchg   %ax,%ax
  407e20:	mov    $0x4193a8,%edi
  407e25:	callq  403650 <Error>
  407e2a:	jmpq   407ceb <Load_Octree+0x11b>
  407e2f:	nop

0000000000407e30 <Store_Octree>:
  407e30:	push   %rbp
  407e31:	push   %rbx
  407e32:	mov    %rdi,%rsi
  407e35:	sub    $0xd8,%rsp
  407e3c:	mov    %rsp,%rdi
  407e3f:	callq  401140 <stpcpy@plt>
  407e44:	mov    %rsp,%rdi
  407e47:	movl   $0x7279702e,(%rax)
  407e4d:	movb   $0x0,0x4(%rax)
  407e51:	callq  403140 <Create_File>
  407e56:	mov    $0x1,%edx
  407e5b:	mov    %eax,%ebp
  407e5d:	mov    %eax,%edi
  407e5f:	mov    %dx,0x23c6d6(%rip)        # 64453c <pyr_version>
  407e66:	mov    $0x64453c,%esi
  407e6b:	mov    $0x2,%edx
  407e70:	callq  403270 <Write_Shorts>
  407e75:	mov    $0x2,%edx
  407e7a:	mov    $0x6445a8,%esi
  407e7f:	mov    %ebp,%edi
  407e81:	callq  403270 <Write_Shorts>
  407e86:	movswl 0x23c71b(%rip),%eax        # 6445a8 <pyr_levels>
  407e8d:	mov    $0x644500,%esi
  407e92:	mov    %ebp,%edi
  407e94:	lea    (%rax,%rax,2),%ecx
  407e97:	movslq %ecx,%rdx
  407e9a:	shl    $0x3,%rdx
  407e9e:	callq  403270 <Write_Shorts>
  407ea3:	movswl 0x23c6fe(%rip),%ebx        # 6445a8 <pyr_levels>
  407eaa:	mov    %ebp,%edi
  407eac:	lea    (%rbx,%rbx,2),%esi
  407eaf:	movslq %esi,%rdx
  407eb2:	mov    $0x644540,%esi
  407eb7:	shl    $0x3,%rdx
  407ebb:	callq  403270 <Write_Shorts>
  407ec0:	movswq 0x23c6e0(%rip),%rdx        # 6445a8 <pyr_levels>
  407ec8:	mov    $0x644580,%esi
  407ecd:	mov    %ebp,%edi
  407ecf:	shl    $0x2,%rdx
  407ed3:	callq  403320 <Write_Longs>
  407ed8:	movswl 0x23c6c9(%rip),%esi        # 6445a8 <pyr_levels>
  407edf:	xor    %eax,%eax
  407ee1:	mov    $0x419508,%edi
  407ee6:	callq  401170 <printf@plt>
  407eeb:	cmpw   $0x0,0x23c6b5(%rip)        # 6445a8 <pyr_levels>
  407ef3:	jle    407f37 <Store_Octree+0x107>
  407ef5:	xor    %ebx,%ebx
  407ef7:	nopw   0x0(%rax,%rax,1)
  407f00:	mov    %rbx,%rsi
  407f03:	mov    $0x419538,%edi
  407f08:	xor    %eax,%eax
  407f0a:	callq  401170 <printf@plt>
  407f0f:	movslq 0x644580(,%rbx,4),%rdx
  407f17:	mov    0x6445c0(,%rbx,8),%rsi
  407f1f:	mov    %ebp,%edi
  407f21:	add    $0x1,%rbx
  407f25:	callq  4031c0 <Write_Bytes>
  407f2a:	movswq 0x23c676(%rip),%rdi        # 6445a8 <pyr_levels>
  407f32:	cmp    %rbx,%rdi
  407f35:	jg     407f00 <Store_Octree+0xd0>
  407f37:	mov    %ebp,%edi
  407f39:	callq  4035e0 <Close_File>
  407f3e:	add    $0xd8,%rsp
  407f45:	pop    %rbx
  407f46:	pop    %rbp
  407f47:	retq   
  407f48:	nopl   0x0(%rax,%rax,1)

0000000000407f50 <Allocate_Opacity>:
  407f50:	push   %rbp
  407f51:	push   %rbx
  407f52:	mov    %rsi,%rbp
  407f55:	mov    %rdi,%rbx
  407f58:	xor    %eax,%eax
  407f5a:	mov    $0x419588,%edi
  407f5f:	sub    $0x8,%rsp
  407f63:	callq  401170 <printf@plt>
  407f68:	mov    %rbp,%rdi
  407f6b:	callq  401270 <malloc@plt>
  407f70:	test   %rax,%rax
  407f73:	mov    %rax,(%rbx)
  407f76:	je     408070 <Allocate_Opacity+0x120>
  407f7c:	test   %rbp,%rbp
  407f7f:	jle    40804e <Allocate_Opacity+0xfe>
  407f85:	mov    %rbp,%rdx
  407f88:	xor    %ecx,%ecx
  407f8a:	and    $0x7,%edx
  407f8d:	je     408002 <Allocate_Opacity+0xb2>
  407f8f:	cmp    $0x1,%rdx
  407f93:	je     407ff1 <Allocate_Opacity+0xa1>
  407f95:	cmp    $0x2,%rdx
  407f99:	je     407fe5 <Allocate_Opacity+0x95>
  407f9b:	cmp    $0x3,%rdx
  407f9f:	je     407fd9 <Allocate_Opacity+0x89>
  407fa1:	cmp    $0x4,%rdx
  407fa5:	je     407fcd <Allocate_Opacity+0x7d>
  407fa7:	cmp    $0x5,%rdx
  407fab:	je     407fc2 <Allocate_Opacity+0x72>
  407fad:	cmp    $0x6,%rdx
  407fb1:	jne    408058 <Allocate_Opacity+0x108>
  407fb7:	mov    (%rbx),%rsi
  407fba:	movb   $0x0,(%rsi,%rcx,1)
  407fbe:	add    $0x1,%rcx
  407fc2:	mov    (%rbx),%rdi
  407fc5:	movb   $0x0,(%rdi,%rcx,1)
  407fc9:	add    $0x1,%rcx
  407fcd:	mov    (%rbx),%r8
  407fd0:	movb   $0x0,(%r8,%rcx,1)
  407fd5:	add    $0x1,%rcx
  407fd9:	mov    (%rbx),%r9
  407fdc:	movb   $0x0,(%r9,%rcx,1)
  407fe1:	add    $0x1,%rcx
  407fe5:	mov    (%rbx),%r10
  407fe8:	movb   $0x0,(%r10,%rcx,1)
  407fed:	add    $0x1,%rcx
  407ff1:	mov    (%rbx),%r11
  407ff4:	movb   $0x0,(%r11,%rcx,1)
  407ff9:	add    $0x1,%rcx
  407ffd:	cmp    %rcx,%rbp
  408000:	je     40804e <Allocate_Opacity+0xfe>
  408002:	mov    (%rbx),%rdx
  408005:	movb   $0x0,(%rdx,%rcx,1)
  408009:	mov    (%rbx),%rax
  40800c:	movb   $0x0,0x1(%rax,%rcx,1)
  408011:	mov    (%rbx),%rsi
  408014:	movb   $0x0,0x2(%rsi,%rcx,1)
  408019:	mov    (%rbx),%rdi
  40801c:	movb   $0x0,0x3(%rdi,%rcx,1)
  408021:	mov    (%rbx),%r8
  408024:	movb   $0x0,0x4(%r8,%rcx,1)
  40802a:	mov    (%rbx),%r9
  40802d:	movb   $0x0,0x5(%r9,%rcx,1)
  408033:	mov    (%rbx),%r10
  408036:	movb   $0x0,0x6(%r10,%rcx,1)
  40803c:	mov    (%rbx),%r11
  40803f:	movb   $0x0,0x7(%r11,%rcx,1)
  408045:	add    $0x8,%rcx
  408049:	cmp    %rcx,%rbp
  40804c:	jne    408002 <Allocate_Opacity+0xb2>
  40804e:	add    $0x8,%rsp
  408052:	pop    %rbx
  408053:	pop    %rbp
  408054:	retq   
  408055:	nopl   (%rax)
  408058:	mov    (%rbx),%rax
  40805b:	mov    $0x1,%ecx
  408060:	movb   $0x0,(%rax)
  408063:	jmpq   407fb7 <Allocate_Opacity+0x67>
  408068:	nopl   0x0(%rax,%rax,1)
  408070:	mov    $0x419238,%edi
  408075:	callq  403650 <Error>
  40807a:	jmpq   407f7c <Allocate_Opacity+0x2c>
  40807f:	nop

0000000000408080 <Opacity_Compute>:
  408080:	push   %r15
  408082:	push   %r14
  408084:	push   %r13
  408086:	push   %r12
  408088:	push   %rbp
  408089:	push   %rbx
  40808a:	sub    $0x48,%rsp
  40808e:	mov    0x23a243(%rip),%rax        # 6422d8 <Global>
  408095:	lea    0x2008e0(%rax),%rdi
  40809c:	callq  401380 <pthread_mutex_lock@plt>
  4080a1:	mov    0x23a230(%rip),%rcx        # 6422d8 <Global>
  4080a8:	mov    (%rcx),%rdx
  4080ab:	lea    0x2008e0(%rcx),%rdi
  4080b2:	add    $0x1,%rdx
  4080b6:	mov    %rdx,(%rcx)
  4080b9:	callq  401260 <pthread_mutex_unlock@plt>
  4080be:	movswq 0x23c54e(%rip),%rsi        # 644614 <opc_len+0x4>
  4080c6:	movswq 0x23c544(%rip),%rbx        # 644612 <opc_len+0x2>
  4080ce:	movswq 0x23c53a(%rip),%rdi        # 644610 <opc_len>
  4080d6:	test   %si,%si
  4080d9:	mov    %rbx,(%rsp)
  4080dd:	jle    408408 <Opacity_Compute+0x388>
  4080e3:	test   %rbx,%rbx
  4080e6:	jle    408408 <Opacity_Compute+0x388>
  4080ec:	test   %rdi,%rdi
  4080ef:	jle    408408 <Opacity_Compute+0x388>
  4080f5:	pxor   %xmm4,%xmm4
  4080f9:	add    $0x2,%rsi
  4080fd:	mov    $0x2,%r8d
  408103:	movsd  0x1154d(%rip),%xmm3        # 419658 <__dso_handle+0x890>
  40810b:	mov    %rsi,0x8(%rsp)
  408110:	lea    -0x2(%r8),%r13
  408114:	lea    -0x1(%r8),%r14
  408118:	mov    $0x2,%r15d
  40811e:	xor    %r12d,%r12d
  408121:	nopl   0x0(%rax)
  408128:	xor    %ebx,%ebx
  40812a:	test   $0x1,%dil
  40812e:	lea    0x1(%r12),%rbp
  408133:	je     4081a9 <Opacity_Compute+0x129>
  408135:	movswq 0x23c371(%rip),%rax        # 6444ae <map_len+0x2>
  40813d:	movswq 0x23c367(%rip),%rsi        # 6444ac <map_len>
  408145:	mov    $0x1,%ebx
  40814a:	mov    0x23c32f(%rip),%rdx        # 644480 <map_address>
  408151:	mov    %rax,%rcx
  408154:	imul   %r14,%rcx
  408158:	lea    (%rcx,%rbp,1),%r9
  40815c:	imul   %rsi,%r9
  408160:	lea    0x1(%r9),%r10
  408164:	movzbl 0x1(%rdx,%r9,1),%r9d
  40816a:	cmp    %r9,0x23d077(%rip)        # 6451e8 <density_epsilon>
  408171:	jl     408520 <Opacity_Compute+0x4a0>
  408177:	movswq 0x23c493(%rip),%r11        # 644612 <opc_len+0x2>
  40817f:	movswq 0x23c489(%rip),%rdx        # 644610 <opc_len>
  408187:	mov    0x23c492(%rip),%rax        # 644620 <opc_address>
  40818e:	imul   %r13,%r11
  408192:	add    %r12,%r11
  408195:	imul   %rdx,%r11
  408199:	movb   $0x0,(%rax,%r11,1)
  40819e:	xchg   %ax,%ax
  4081a0:	cmp    %rbx,%rdi
  4081a3:	je     4083e8 <Opacity_Compute+0x368>
  4081a9:	movswq 0x23c2fd(%rip),%rdx        # 6444ae <map_len+0x2>
  4081b1:	movswq 0x23c2f3(%rip),%r9        # 6444ac <map_len>
  4081b9:	add    $0x1,%rbx
  4081bd:	mov    0x23c2bc(%rip),%rcx        # 644480 <map_address>
  4081c4:	mov    %rdx,%rsi
  4081c7:	imul   %r14,%rsi
  4081cb:	lea    (%rsi,%rbp,1),%rax
  4081cf:	imul   %r9,%rax
  4081d3:	add    %rbx,%rax
  4081d6:	movzbl (%rcx,%rax,1),%r10d
  4081db:	cmp    %r10,0x23d006(%rip)        # 6451e8 <density_epsilon>
  4081e2:	jge    408450 <Opacity_Compute+0x3d0>
  4081e8:	movzbl 0x1(%rcx,%rax,1),%r11d
  4081ee:	movzbl -0x1(%rcx,%rax,1),%eax
  4081f3:	add    %rbx,%rcx
  4081f6:	pxor   %xmm8,%xmm8
  4081fb:	pxor   %xmm9,%xmm9
  408200:	pxor   %xmm10,%xmm10
  408205:	sub    %rax,%r11
  408208:	lea    (%r15,%rsi,1),%rax
  40820c:	add    %r12,%rsi
  40820f:	cvtsi2ss %r11,%xmm8
  408214:	imul   %r9,%rax
  408218:	imul   %r9,%rsi
  40821c:	movzbl (%rcx,%rax,1),%r11d
  408221:	mov    %r8,%rax
  408224:	imul   %rdx,%rax
  408228:	movzbl (%rcx,%rsi,1),%esi
  40822c:	imul   %r13,%rdx
  408230:	add    %rbp,%rax
  408233:	sub    %rsi,%r11
  408236:	add    %rbp,%rdx
  408239:	imul   %r9,%rax
  40823d:	imul   %r9,%rdx
  408241:	cvtsi2ss %r11,%xmm9
  408246:	movzbl (%rcx,%rax,1),%r11d
  40824b:	mulss  %xmm8,%xmm8
  408250:	movzbl (%rcx,%rdx,1),%edx
  408254:	sub    %rdx,%r11
  408257:	cvtsi2ss %r11,%xmm10
  40825c:	mulss  %xmm9,%xmm9
  408261:	addss  %xmm8,%xmm9
  408266:	mulss  %xmm10,%xmm10
  40826b:	addss  %xmm9,%xmm10
  408270:	ucomiss 0x23c24c(%rip),%xmm10        # 6444c4 <nmag_epsilon>
  408278:	ja     408480 <Opacity_Compute+0x400>
  40827e:	movswq 0x23c228(%rip),%rdx        # 6444ae <map_len+0x2>
  408286:	movswq 0x23c21e(%rip),%r9        # 6444ac <map_len>
  40828e:	add    $0x1,%rbx
  408292:	mov    0x23c1e7(%rip),%rcx        # 644480 <map_address>
  408299:	mov    %rdx,%rsi
  40829c:	imul   %r14,%rsi
  4082a0:	lea    (%rsi,%rbp,1),%rax
  4082a4:	imul   %r9,%rax
  4082a8:	add    %rbx,%rax
  4082ab:	movzbl (%rcx,%rax,1),%r10d
  4082b0:	cmp    %r10,0x23cf31(%rip)        # 6451e8 <density_epsilon>
  4082b7:	jge    408420 <Opacity_Compute+0x3a0>
  4082bd:	movzbl 0x1(%rcx,%rax,1),%r11d
  4082c3:	movzbl -0x1(%rcx,%rax,1),%eax
  4082c8:	add    %rbx,%rcx
  4082cb:	pxor   %xmm15,%xmm15
  4082d0:	pxor   %xmm2,%xmm2
  4082d4:	pxor   %xmm1,%xmm1
  4082d8:	sub    %rax,%r11
  4082db:	lea    (%r15,%rsi,1),%rax
  4082df:	add    %r12,%rsi
  4082e2:	cvtsi2ss %r11,%xmm15
  4082e7:	imul   %r9,%rax
  4082eb:	imul   %r9,%rsi
  4082ef:	movzbl (%rcx,%rax,1),%r11d
  4082f4:	mov    %r8,%rax
  4082f7:	imul   %rdx,%rax
  4082fb:	movzbl (%rcx,%rsi,1),%esi
  4082ff:	imul   %r13,%rdx
  408303:	add    %rbp,%rax
  408306:	sub    %rsi,%r11
  408309:	add    %rbp,%rdx
  40830c:	imul   %r9,%rax
  408310:	imul   %r9,%rdx
  408314:	cvtsi2ss %r11,%xmm2
  408319:	movzbl (%rcx,%rax,1),%r11d
  40831e:	mulss  %xmm15,%xmm15
  408323:	movzbl (%rcx,%rdx,1),%edx
  408327:	sub    %rdx,%r11
  40832a:	cvtsi2ss %r11,%xmm1
  40832f:	mulss  %xmm2,%xmm2
  408333:	addss  %xmm15,%xmm2
  408338:	mulss  %xmm1,%xmm1
  40833c:	addss  %xmm2,%xmm1
  408340:	ucomiss 0x23c17d(%rip),%xmm1        # 6444c4 <nmag_epsilon>
  408347:	jbe    4081a0 <Opacity_Compute+0x120>
  40834d:	pxor   %xmm0,%xmm0
  408351:	cvtss2sd %xmm1,%xmm0
  408355:	ucomisd %xmm0,%xmm4
  408359:	sqrtsd %xmm0,%xmm5
  40835d:	ja     4085f7 <Opacity_Compute+0x577>
  408363:	mulsd  %xmm3,%xmm5
  408367:	pxor   %xmm0,%xmm0
  40836b:	cvtsd2ss %xmm5,%xmm0
  40836f:	cvttss2si %xmm0,%r9
  408374:	movss  0x644a80(,%r9,4),%xmm6
  40837e:	mulss  0x644660(,%r10,4),%xmm6
  408388:	ucomiss 0x23ce61(%rip),%xmm6        # 6451f0 <opacity_epsilon>
  40838f:	jbe    4081a0 <Opacity_Compute+0x120>
  408395:	mulss  0x112c3(%rip),%xmm6        # 419660 <__dso_handle+0x898>
  40839d:	movswq 0x23c26d(%rip),%rax        # 644612 <opc_len+0x2>
  4083a5:	pxor   %xmm7,%xmm7
  4083a9:	movswq 0x23c25f(%rip),%rcx        # 644610 <opc_len>
  4083b1:	mov    0x23c268(%rip),%r11        # 644620 <opc_address>
  4083b8:	imul   %r13,%rax
  4083bc:	add    %rbx,%r11
  4083bf:	cvtss2sd %xmm6,%xmm7
  4083c3:	addsd  %xmm3,%xmm7
  4083c7:	add    %r12,%rax
  4083ca:	imul   %rcx,%rax
  4083ce:	cmp    %rbx,%rdi
  4083d1:	cvttsd2si %xmm7,%r10
  4083d6:	mov    %r10b,-0x1(%rax,%r11,1)
  4083db:	jne    4081a9 <Opacity_Compute+0x129>
  4083e1:	nopl   0x0(%rax)
  4083e8:	add    $0x1,%r15
  4083ec:	cmp    %rbp,(%rsp)
  4083f0:	mov    %rbp,%r12
  4083f3:	jne    408128 <Opacity_Compute+0xa8>
  4083f9:	add    $0x1,%r8
  4083fd:	cmp    %r8,0x8(%rsp)
  408402:	jne    408110 <Opacity_Compute+0x90>
  408408:	add    $0x48,%rsp
  40840c:	pop    %rbx
  40840d:	pop    %rbp
  40840e:	pop    %r12
  408410:	pop    %r13
  408412:	pop    %r14
  408414:	pop    %r15
  408416:	retq   
  408417:	nopw   0x0(%rax,%rax,1)
  408420:	movswq 0x23c1ea(%rip),%r10        # 644612 <opc_len+0x2>
  408428:	movswq 0x23c1e0(%rip),%r11        # 644610 <opc_len>
  408430:	mov    0x23c1e9(%rip),%rcx        # 644620 <opc_address>
  408437:	imul   %r13,%r10
  40843b:	add    %rbx,%rcx
  40843e:	add    %r12,%r10
  408441:	imul   %r11,%r10
  408445:	movb   $0x0,-0x1(%r10,%rcx,1)
  40844b:	jmpq   4081a0 <Opacity_Compute+0x120>
  408450:	movswq 0x23c1ba(%rip),%r11        # 644612 <opc_len+0x2>
  408458:	movswq 0x23c1b0(%rip),%r10        # 644610 <opc_len>
  408460:	mov    0x23c1b9(%rip),%rcx        # 644620 <opc_address>
  408467:	imul   %r13,%r11
  40846b:	add    %rbx,%rcx
  40846e:	add    %r12,%r11
  408471:	imul   %r10,%r11
  408475:	movb   $0x0,-0x1(%r11,%rcx,1)
  40847b:	jmpq   40827e <Opacity_Compute+0x1fe>
  408480:	pxor   %xmm0,%xmm0
  408484:	cvtss2sd %xmm10,%xmm0
  408489:	ucomisd %xmm0,%xmm4
  40848d:	sqrtsd %xmm0,%xmm11
  408492:	ja     408643 <Opacity_Compute+0x5c3>
  408498:	mulsd  %xmm3,%xmm11
  40849d:	pxor   %xmm12,%xmm12
  4084a2:	cvtsd2ss %xmm11,%xmm12
  4084a7:	cvttss2si %xmm12,%r9
  4084ac:	movss  0x644a80(,%r9,4),%xmm13
  4084b6:	mulss  0x644660(,%r10,4),%xmm13
  4084c0:	ucomiss 0x23cd28(%rip),%xmm13        # 6451f0 <opacity_epsilon>
  4084c8:	jbe    40827e <Opacity_Compute+0x1fe>
  4084ce:	mulss  0x11189(%rip),%xmm13        # 419660 <__dso_handle+0x898>
  4084d7:	movswq 0x23c133(%rip),%rsi        # 644612 <opc_len+0x2>
  4084df:	pxor   %xmm14,%xmm14
  4084e4:	movswq 0x23c124(%rip),%rcx        # 644610 <opc_len>
  4084ec:	mov    0x23c12d(%rip),%rax        # 644620 <opc_address>
  4084f3:	imul   %r13,%rsi
  4084f7:	add    %rbx,%rax
  4084fa:	cvtss2sd %xmm13,%xmm14
  4084ff:	addsd  %xmm3,%xmm14
  408504:	add    %r12,%rsi
  408507:	imul   %rcx,%rsi
  40850b:	cvttsd2si %xmm14,%r11
  408510:	mov    %r11b,-0x1(%rsi,%rax,1)
  408515:	jmpq   40827e <Opacity_Compute+0x1fe>
  40851a:	nopw   0x0(%rax,%rax,1)
  408520:	movzbl 0x1(%rdx,%r10,1),%r11d
  408526:	movzbl -0x1(%rdx,%r10,1),%r10d
  40852c:	pxor   %xmm2,%xmm2
  408530:	pxor   %xmm1,%xmm1
  408534:	pxor   %xmm0,%xmm0
  408538:	sub    %r10,%r11
  40853b:	cvtsi2ss %r11,%xmm2
  408540:	lea    (%r15,%rcx,1),%r11
  408544:	add    %r12,%rcx
  408547:	imul   %rsi,%rcx
  40854b:	imul   %rsi,%r11
  40854f:	movzbl 0x1(%rdx,%rcx,1),%ecx
  408554:	movzbl 0x1(%rdx,%r11,1),%r10d
  40855a:	mov    %r8,%r11
  40855d:	imul   %rax,%r11
  408561:	imul   %r13,%rax
  408565:	sub    %rcx,%r10
  408568:	add    %rbp,%r11
  40856b:	add    %rbp,%rax
  40856e:	imul   %rsi,%r11
  408572:	mulss  %xmm2,%xmm2
  408576:	imul   %rax,%rsi
  40857a:	cvtsi2ss %r10,%xmm1
  40857f:	movzbl 0x1(%rdx,%r11,1),%r10d
  408585:	movzbl 0x1(%rdx,%rsi,1),%esi
  40858a:	sub    %rsi,%r10
  40858d:	cvtsi2ss %r10,%xmm0
  408592:	mulss  %xmm1,%xmm1
  408596:	addss  %xmm2,%xmm1
  40859a:	mulss  %xmm0,%xmm0
  40859e:	addss  %xmm1,%xmm0
  4085a2:	ucomiss 0x23bf1b(%rip),%xmm0        # 6444c4 <nmag_epsilon>
  4085a9:	jbe    4081a0 <Opacity_Compute+0x120>
  4085af:	cvtss2sd %xmm0,%xmm0
  4085b3:	ucomisd %xmm0,%xmm4
  4085b7:	sqrtsd %xmm0,%xmm5
  4085bb:	ja     408691 <Opacity_Compute+0x611>
  4085c1:	mulsd  %xmm3,%xmm5
  4085c5:	pxor   %xmm6,%xmm6
  4085c9:	cvtsd2ss %xmm5,%xmm6
  4085cd:	cvttss2si %xmm6,%rdx
  4085d2:	movss  0x644a80(,%rdx,4),%xmm6
  4085db:	mulss  0x644660(,%r9,4),%xmm6
  4085e5:	ucomiss 0x23cc04(%rip),%xmm6        # 6451f0 <opacity_epsilon>
  4085ec:	jbe    4081a0 <Opacity_Compute+0x120>
  4085f2:	jmpq   408395 <Opacity_Compute+0x315>
  4085f7:	mov    %r8,0x38(%rsp)
  4085fc:	mov    %rdi,0x30(%rsp)
  408601:	movsd  %xmm5,0x28(%rsp)
  408607:	mov    %r10,0x20(%rsp)
  40860c:	movsd  %xmm3,0x18(%rsp)
  408612:	movsd  %xmm4,0x10(%rsp)
  408618:	callq  401360 <sqrt@plt>
  40861d:	movsd  0x10(%rsp),%xmm4
  408623:	movsd  0x18(%rsp),%xmm3
  408629:	mov    0x20(%rsp),%r10
  40862e:	movsd  0x28(%rsp),%xmm5
  408634:	mov    0x30(%rsp),%rdi
  408639:	mov    0x38(%rsp),%r8
  40863e:	jmpq   408363 <Opacity_Compute+0x2e3>
  408643:	mov    %r8,0x38(%rsp)
  408648:	mov    %rdi,0x30(%rsp)
  40864d:	movsd  %xmm3,0x28(%rsp)
  408653:	movsd  %xmm4,0x20(%rsp)
  408659:	mov    %r10,0x18(%rsp)
  40865e:	movsd  %xmm11,0x10(%rsp)
  408665:	callq  401360 <sqrt@plt>
  40866a:	mov    0x38(%rsp),%r8
  40866f:	mov    0x30(%rsp),%rdi
  408674:	movsd  0x28(%rsp),%xmm3
  40867a:	movsd  0x20(%rsp),%xmm4
  408680:	mov    0x18(%rsp),%r10
  408685:	movsd  0x10(%rsp),%xmm11
  40868c:	jmpq   408498 <Opacity_Compute+0x418>
  408691:	mov    %r8,0x38(%rsp)
  408696:	mov    %rdi,0x30(%rsp)
  40869b:	movsd  %xmm5,0x28(%rsp)
  4086a1:	mov    %r9,0x20(%rsp)
  4086a6:	movsd  %xmm3,0x18(%rsp)
  4086ac:	movsd  %xmm4,0x10(%rsp)
  4086b2:	callq  401360 <sqrt@plt>
  4086b7:	movsd  0x10(%rsp),%xmm4
  4086bd:	movsd  0x18(%rsp),%xmm3
  4086c3:	mov    0x20(%rsp),%r9
  4086c8:	movsd  0x28(%rsp),%xmm5
  4086ce:	mov    0x30(%rsp),%rdi
  4086d3:	mov    0x38(%rsp),%r8
  4086d8:	jmpq   4085c1 <Opacity_Compute+0x541>
  4086dd:	nopl   (%rax)

00000000004086e0 <Compute_Opacity>:
  4086e0:	movzwl 0x23bdc5(%rip),%eax        # 6444ac <map_len>
  4086e7:	movzwl 0x23bdc0(%rip),%edx        # 6444ae <map_len+0x2>
  4086ee:	push   %rbx
  4086ef:	lea    -0x2(%rdx),%ecx
  4086f2:	lea    -0x2(%rax),%ebx
  4086f5:	movzwl 0x23bdb4(%rip),%eax        # 6444b0 <map_len+0x4>
  4086fc:	movswl %cx,%edi
  4086ff:	movswl %bx,%esi
  408702:	mov    %bx,0x23bf07(%rip)        # 644610 <opc_len>
  408709:	imul   %edi,%esi
  40870c:	mov    $0x419588,%edi
  408711:	mov    %cx,0x23befa(%rip)        # 644612 <opc_len+0x2>
  408718:	sub    $0x2,%eax
  40871b:	mov    %ax,0x23bef2(%rip)        # 644614 <opc_len+0x4>
  408722:	cwtl   
  408723:	imul   %eax,%esi
  408726:	xor    %eax,%eax
  408728:	movslq %esi,%rbx
  40872b:	mov    %esi,0x23bee7(%rip)        # 644618 <opc_length>
  408731:	mov    %rbx,%rsi
  408734:	callq  401170 <printf@plt>
  408739:	mov    %rbx,%rdi
  40873c:	callq  401270 <malloc@plt>
  408741:	test   %rax,%rax
  408744:	mov    %rax,0x23bed5(%rip)        # 644620 <opc_address>
  40874b:	je     4088a0 <Compute_Opacity+0x1c0>
  408751:	test   %rbx,%rbx
  408754:	jle    408867 <Compute_Opacity+0x187>
  40875a:	mov    %rbx,%r8
  40875d:	xor    %r10d,%r10d
  408760:	and    $0x7,%r8d
  408764:	je     4087f7 <Compute_Opacity+0x117>
  40876a:	cmp    $0x1,%r8
  40876e:	je     4087e2 <Compute_Opacity+0x102>
  408770:	cmp    $0x2,%r8
  408774:	je     4087d2 <Compute_Opacity+0xf2>
  408776:	cmp    $0x3,%r8
  40877a:	je     4087c2 <Compute_Opacity+0xe2>
  40877c:	cmp    $0x4,%r8
  408780:	je     4087b2 <Compute_Opacity+0xd2>
  408782:	cmp    $0x5,%r8
  408786:	je     4087a2 <Compute_Opacity+0xc2>
  408788:	cmp    $0x6,%r8
  40878c:	jne    408888 <Compute_Opacity+0x1a8>
  408792:	mov    0x23be87(%rip),%r11        # 644620 <opc_address>
  408799:	movb   $0x0,(%r11,%r10,1)
  40879e:	add    $0x1,%r10
  4087a2:	mov    0x23be77(%rip),%rdx        # 644620 <opc_address>
  4087a9:	movb   $0x0,(%rdx,%r10,1)
  4087ae:	add    $0x1,%r10
  4087b2:	mov    0x23be67(%rip),%rcx        # 644620 <opc_address>
  4087b9:	movb   $0x0,(%rcx,%r10,1)
  4087be:	add    $0x1,%r10
  4087c2:	mov    0x23be57(%rip),%rax        # 644620 <opc_address>
  4087c9:	movb   $0x0,(%rax,%r10,1)
  4087ce:	add    $0x1,%r10
  4087d2:	mov    0x23be47(%rip),%rsi        # 644620 <opc_address>
  4087d9:	movb   $0x0,(%rsi,%r10,1)
  4087de:	add    $0x1,%r10
  4087e2:	mov    0x23be37(%rip),%rdi        # 644620 <opc_address>
  4087e9:	movb   $0x0,(%rdi,%r10,1)
  4087ee:	add    $0x1,%r10
  4087f2:	cmp    %r10,%rbx
  4087f5:	je     408867 <Compute_Opacity+0x187>
  4087f7:	mov    0x23be22(%rip),%r8        # 644620 <opc_address>
  4087fe:	movb   $0x0,(%r8,%r10,1)
  408803:	mov    0x23be16(%rip),%r9        # 644620 <opc_address>
  40880a:	movb   $0x0,0x1(%r9,%r10,1)
  408810:	mov    0x23be09(%rip),%r11        # 644620 <opc_address>
  408817:	movb   $0x0,0x2(%r11,%r10,1)
  40881d:	mov    0x23bdfc(%rip),%rdx        # 644620 <opc_address>
  408824:	movb   $0x0,0x3(%rdx,%r10,1)
  40882a:	mov    0x23bdef(%rip),%rcx        # 644620 <opc_address>
  408831:	movb   $0x0,0x4(%rcx,%r10,1)
  408837:	mov    0x23bde2(%rip),%rax        # 644620 <opc_address>
  40883e:	movb   $0x0,0x5(%rax,%r10,1)
  408844:	mov    0x23bdd5(%rip),%rsi        # 644620 <opc_address>
  40884b:	movb   $0x0,0x6(%rsi,%r10,1)
  408851:	mov    0x23bdc8(%rip),%rdi        # 644620 <opc_address>
  408858:	movb   $0x0,0x7(%rdi,%r10,1)
  40885e:	add    $0x8,%r10
  408862:	cmp    %r10,%rbx
  408865:	jne    4087f7 <Compute_Opacity+0x117>
  408867:	mov    $0x419638,%edi
  40886c:	callq  401110 <puts@plt>
  408871:	mov    0x239a60(%rip),%rbx        # 6422d8 <Global>
  408878:	movq   $0x0,(%rbx)
  40887f:	pop    %rbx
  408880:	jmpq   408080 <Opacity_Compute>
  408885:	nopl   (%rax)
  408888:	mov    0x23bd91(%rip),%r9        # 644620 <opc_address>
  40888f:	mov    $0x1,%r10d
  408895:	movb   $0x0,(%r9)
  408899:	jmpq   408792 <Compute_Opacity+0xb2>
  40889e:	xchg   %ax,%ax
  4088a0:	mov    $0x419238,%edi
  4088a5:	callq  403650 <Error>
  4088aa:	jmpq   408751 <Compute_Opacity+0x71>
  4088af:	nop

00000000004088b0 <Load_Opacity>:
  4088b0:	push   %rbp
  4088b1:	push   %rbx
  4088b2:	mov    %rdi,%rsi
  4088b5:	sub    $0xd8,%rsp
  4088bc:	mov    %rsp,%rdi
  4088bf:	callq  401140 <stpcpy@plt>
  4088c4:	mov    %rsp,%rdi
  4088c7:	movl   $0x63706f2e,(%rax)
  4088cd:	movb   $0x0,0x4(%rax)
  4088d1:	callq  403180 <Open_File>
  4088d6:	mov    $0x644628,%esi
  4088db:	mov    $0x2,%edx
  4088e0:	mov    %eax,%edi
  4088e2:	mov    %eax,%ebp
  4088e4:	callq  403480 <Read_Shorts>
  4088e9:	movswl 0x23bd38(%rip),%esi        # 644628 <opc_version>
  4088f0:	cmp    $0x1,%si
  4088f4:	je     408902 <Load_Opacity+0x52>
  4088f6:	mov    $0x4191e8,%edi
  4088fb:	xor    %eax,%eax
  4088fd:	callq  403650 <Error>
  408902:	mov    $0x6,%edx
  408907:	mov    $0x644610,%esi
  40890c:	mov    %ebp,%edi
  40890e:	callq  403480 <Read_Shorts>
  408913:	mov    $0x4,%edx
  408918:	mov    $0x644618,%esi
  40891d:	mov    %ebp,%edi
  40891f:	callq  403530 <Read_Longs>
  408924:	movslq 0x23bced(%rip),%rbx        # 644618 <opc_length>
  40892b:	mov    $0x419588,%edi
  408930:	xor    %eax,%eax
  408932:	mov    %rbx,%rsi
  408935:	callq  401170 <printf@plt>
  40893a:	mov    %rbx,%rdi
  40893d:	callq  401270 <malloc@plt>
  408942:	test   %rax,%rax
  408945:	mov    %rax,0x23bcd4(%rip)        # 644620 <opc_address>
  40894c:	je     408aa8 <Load_Opacity+0x1f8>
  408952:	test   %rbx,%rbx
  408955:	jle    408a60 <Load_Opacity+0x1b0>
  40895b:	mov    %rbx,%rdx
  40895e:	xor    %ecx,%ecx
  408960:	and    $0x7,%edx
  408963:	je     4089f4 <Load_Opacity+0x144>
  408969:	cmp    $0x1,%rdx
  40896d:	je     4089df <Load_Opacity+0x12f>
  40896f:	cmp    $0x2,%rdx
  408973:	je     4089cf <Load_Opacity+0x11f>
  408975:	cmp    $0x3,%rdx
  408979:	je     4089bf <Load_Opacity+0x10f>
  40897b:	cmp    $0x4,%rdx
  40897f:	je     4089af <Load_Opacity+0xff>
  408981:	cmp    $0x5,%rdx
  408985:	je     4089a0 <Load_Opacity+0xf0>
  408987:	cmp    $0x6,%rdx
  40898b:	jne    408a90 <Load_Opacity+0x1e0>
  408991:	mov    0x23bc88(%rip),%rsi        # 644620 <opc_address>
  408998:	movb   $0x0,(%rsi,%rcx,1)
  40899c:	add    $0x1,%rcx
  4089a0:	mov    0x23bc79(%rip),%rdi        # 644620 <opc_address>
  4089a7:	movb   $0x0,(%rdi,%rcx,1)
  4089ab:	add    $0x1,%rcx
  4089af:	mov    0x23bc6a(%rip),%r8        # 644620 <opc_address>
  4089b6:	movb   $0x0,(%r8,%rcx,1)
  4089bb:	add    $0x1,%rcx
  4089bf:	mov    0x23bc5a(%rip),%r9        # 644620 <opc_address>
  4089c6:	movb   $0x0,(%r9,%rcx,1)
  4089cb:	add    $0x1,%rcx
  4089cf:	mov    0x23bc4a(%rip),%r10        # 644620 <opc_address>
  4089d6:	movb   $0x0,(%r10,%rcx,1)
  4089db:	add    $0x1,%rcx
  4089df:	mov    0x23bc3a(%rip),%r11        # 644620 <opc_address>
  4089e6:	movb   $0x0,(%r11,%rcx,1)
  4089eb:	add    $0x1,%rcx
  4089ef:	cmp    %rcx,%rbx
  4089f2:	je     408a60 <Load_Opacity+0x1b0>
  4089f4:	mov    0x23bc25(%rip),%rdx        # 644620 <opc_address>
  4089fb:	movb   $0x0,(%rdx,%rcx,1)
  4089ff:	mov    0x23bc1a(%rip),%rax        # 644620 <opc_address>
  408a06:	movb   $0x0,0x1(%rax,%rcx,1)
  408a0b:	mov    0x23bc0e(%rip),%rsi        # 644620 <opc_address>
  408a12:	movb   $0x0,0x2(%rsi,%rcx,1)
  408a17:	mov    0x23bc02(%rip),%rdi        # 644620 <opc_address>
  408a1e:	movb   $0x0,0x3(%rdi,%rcx,1)
  408a23:	mov    0x23bbf6(%rip),%r8        # 644620 <opc_address>
  408a2a:	movb   $0x0,0x4(%r8,%rcx,1)
  408a30:	mov    0x23bbe9(%rip),%r9        # 644620 <opc_address>
  408a37:	movb   $0x0,0x5(%r9,%rcx,1)
  408a3d:	mov    0x23bbdc(%rip),%r10        # 644620 <opc_address>
  408a44:	movb   $0x0,0x6(%r10,%rcx,1)
  408a4a:	mov    0x23bbcf(%rip),%r11        # 644620 <opc_address>
  408a51:	movb   $0x0,0x7(%r11,%rcx,1)
  408a57:	add    $0x8,%rcx
  408a5b:	cmp    %rcx,%rbx
  408a5e:	jne    4089f4 <Load_Opacity+0x144>
  408a60:	mov    $0x4195b8,%edi
  408a65:	callq  401110 <puts@plt>
  408a6a:	movslq 0x23bba7(%rip),%rdx        # 644618 <opc_length>
  408a71:	mov    0x23bba8(%rip),%rsi        # 644620 <opc_address>
  408a78:	mov    %ebp,%edi
  408a7a:	callq  4033d0 <Read_Bytes>
  408a7f:	mov    %ebp,%edi
  408a81:	callq  4035e0 <Close_File>
  408a86:	add    $0xd8,%rsp
  408a8d:	pop    %rbx
  408a8e:	pop    %rbp
  408a8f:	retq   
  408a90:	mov    0x23bb89(%rip),%rax        # 644620 <opc_address>
  408a97:	mov    $0x1,%ecx
  408a9c:	movb   $0x0,(%rax)
  408a9f:	jmpq   408991 <Load_Opacity+0xe1>
  408aa4:	nopl   0x0(%rax)
  408aa8:	mov    $0x419238,%edi
  408aad:	callq  403650 <Error>
  408ab2:	jmpq   408952 <Load_Opacity+0xa2>
  408ab7:	nopw   0x0(%rax,%rax,1)

0000000000408ac0 <Store_Opacity>:
  408ac0:	push   %rbx
  408ac1:	mov    %rdi,%rsi
  408ac4:	mov    %rdi,%rbx
  408ac7:	sub    $0xd0,%rsp
  408ace:	mov    %rsp,%rdi
  408ad1:	callq  401140 <stpcpy@plt>
  408ad6:	mov    %rsp,%rdi
  408ad9:	movl   $0x63706f2e,(%rax)
  408adf:	movb   $0x0,0x4(%rax)
  408ae3:	callq  403140 <Create_File>
  408ae8:	mov    %rbx,%rsi
  408aeb:	mov    %rsp,%rdi
  408aee:	mov    $0x1,%eax
  408af3:	mov    %ax,0x23bb2e(%rip)        # 644628 <opc_version>
  408afa:	callq  401140 <stpcpy@plt>
  408aff:	mov    %rsp,%rdi
  408b02:	movl   $0x63706f2e,(%rax)
  408b08:	movb   $0x0,0x4(%rax)
  408b0c:	callq  403140 <Create_File>
  408b11:	mov    $0x2,%edx
  408b16:	mov    %eax,%ebx
  408b18:	mov    %eax,%edi
  408b1a:	mov    $0x644628,%esi
  408b1f:	callq  403270 <Write_Shorts>
  408b24:	mov    %ebx,%edi
  408b26:	mov    $0x6,%edx
  408b2b:	mov    $0x644610,%esi
  408b30:	callq  403270 <Write_Shorts>
  408b35:	mov    $0x4,%edx
  408b3a:	mov    $0x644618,%esi
  408b3f:	mov    %ebx,%edi
  408b41:	callq  403320 <Write_Longs>
  408b46:	mov    $0x4195e8,%edi
  408b4b:	callq  401110 <puts@plt>
  408b50:	movslq 0x23bac1(%rip),%rdx        # 644618 <opc_length>
  408b57:	mov    0x23bac2(%rip),%rsi        # 644620 <opc_address>
  408b5e:	mov    %ebx,%edi
  408b60:	callq  4031c0 <Write_Bytes>
  408b65:	mov    %ebx,%edi
  408b67:	callq  4035e0 <Close_File>
  408b6c:	add    $0xd0,%rsp
  408b73:	pop    %rbx
  408b74:	retq   
  408b75:	nop
  408b76:	nopw   %cs:0x0(%rax,%rax,1)

0000000000408b80 <Deallocate_Opacity>:
  408b80:	push   %rbx
  408b81:	mov    %rdi,%rbx
  408b84:	mov    $0x419618,%edi
  408b89:	callq  401110 <puts@plt>
  408b8e:	movq   $0x0,(%rbx)
  408b95:	pop    %rbx
  408b96:	retq   
  408b97:	nopw   0x0(%rax,%rax,1)

0000000000408ba0 <Init_Opacity>:
  408ba0:	movss  0x10ce8(%rip),%xmm2        # 419890 <__dso_handle+0xac8>
  408ba8:	mov    $0x644660,%edi
  408bad:	mov    $0x2f,%ecx
  408bb2:	xor    %eax,%eax
  408bb4:	movl   $0x0,0x23bc1e(%rip)        # 6447dc <density_opacity+0x17c>
  408bbe:	rep stos %rax,%es:(%rdi)
  408bc1:	movaps %xmm2,%xmm0
  408bc4:	movq   $0x60,0x23c619(%rip)        # 6451e8 <density_epsilon>
  408bcf:	movss  0x10225(%rip),%xmm1        # 418dfc <__dso_handle+0x34>
  408bd7:	movq   $0x1,0x23c5ae(%rip)        # 645190 <magnitude_epsilon>
  408be2:	addss  %xmm2,%xmm0
  408be6:	movss  %xmm1,0x23be6e(%rip)        # 644a5c <density_opacity+0x3fc>
  408bee:	mov    $0x6447ec,%edx
  408bf3:	movl   $0x0,(%rdi)
  408bf9:	movss  %xmm2,0x23bbdf(%rip)        # 6447e0 <density_opacity+0x180>
  408c01:	movss  %xmm0,0x23bbdb(%rip)        # 6447e4 <density_opacity+0x184>
  408c09:	addss  %xmm2,%xmm0
  408c0d:	movss  %xmm0,0x23bbd3(%rip)        # 6447e8 <density_opacity+0x188>
  408c15:	nopl   (%rax)
  408c18:	addss  %xmm2,%xmm0
  408c1c:	add    $0x24,%rdx
  408c20:	movss  %xmm0,-0x24(%rdx)
  408c25:	addss  %xmm2,%xmm0
  408c29:	movss  %xmm0,-0x20(%rdx)
  408c2e:	addss  %xmm2,%xmm0
  408c32:	movss  %xmm0,-0x1c(%rdx)
  408c37:	addss  %xmm2,%xmm0
  408c3b:	movss  %xmm0,-0x18(%rdx)
  408c40:	addss  %xmm2,%xmm0
  408c44:	movss  %xmm0,-0x14(%rdx)
  408c49:	addss  %xmm2,%xmm0
  408c4d:	movss  %xmm0,-0x10(%rdx)
  408c52:	addss  %xmm2,%xmm0
  408c56:	movss  %xmm0,-0xc(%rdx)
  408c5b:	addss  %xmm2,%xmm0
  408c5f:	movss  %xmm0,-0x8(%rdx)
  408c64:	addss  %xmm2,%xmm0
  408c68:	movss  %xmm0,-0x4(%rdx)
  408c6d:	cmp    $0x64487c,%rdx
  408c74:	jne    408c18 <Init_Opacity+0x78>
  408c76:	movaps 0x10c23(%rip),%xmm3        # 4198a0 <__dso_handle+0xad8>
  408c7d:	mov    $0x6448a0,%esi
  408c82:	movaps %xmm3,0x23bbf7(%rip)        # 644880 <density_opacity+0x220>
  408c89:	movaps %xmm3,0x23bc00(%rip)        # 644890 <density_opacity+0x230>
  408c90:	movss  %xmm1,0x23bbe4(%rip)        # 64487c <density_opacity+0x21c>
  408c98:	movaps %xmm3,(%rsi)
  408c9b:	add    $0x90,%rsi
  408ca2:	movaps %xmm3,-0x80(%rsi)
  408ca6:	movaps %xmm3,-0x70(%rsi)
  408caa:	movaps %xmm3,-0x60(%rsi)
  408cae:	movaps %xmm3,-0x50(%rsi)
  408cb2:	movaps %xmm3,-0x40(%rsi)
  408cb6:	movaps %xmm3,-0x30(%rsi)
  408cba:	movaps %xmm3,-0x20(%rsi)
  408cbe:	movaps %xmm3,-0x10(%rsi)
  408cc2:	cmp    $0x644a50,%rsi
  408cc9:	jne    408c98 <Init_Opacity+0xf8>
  408ccb:	movss  0x10bc1(%rip),%xmm4        # 419894 <__dso_handle+0xacc>
  408cd3:	movabs $0x3f8000003f800000,%r8
  408cdd:	movaps %xmm4,%xmm5
  408ce0:	movss  %xmm1,0x23c480(%rip)        # 645168 <magnitude_opacity+0x6e8>
  408ce8:	movss  %xmm4,0x23bd94(%rip)        # 644a84 <magnitude_opacity+0x4>
  408cf0:	mov    %r8,0x23bd59(%rip)        # 644a50 <density_opacity+0x3f0>
  408cf7:	movl   $0x3f800000,0x23bd57(%rip)        # 644a58 <density_opacity+0x3f8>
  408d01:	addss  %xmm4,%xmm5
  408d05:	movl   $0x0,0x23bd71(%rip)        # 644a80 <magnitude_opacity>
  408d0f:	mov    $0x644b98,%r9d
  408d15:	mov    $0x644a98,%r10d
  408d1b:	movss  %xmm5,0x23bd65(%rip)        # 644a88 <magnitude_opacity+0x8>
  408d23:	addss  %xmm4,%xmm5
  408d27:	movss  %xmm5,0x23bd5d(%rip)        # 644a8c <magnitude_opacity+0xc>
  408d2f:	addss  %xmm4,%xmm5
  408d33:	movss  %xmm5,0x23bd55(%rip)        # 644a90 <magnitude_opacity+0x10>
  408d3b:	addss  %xmm4,%xmm5
  408d3f:	movss  %xmm5,0x23bd4d(%rip)        # 644a94 <magnitude_opacity+0x14>
  408d47:	nopw   0x0(%rax,%rax,1)
  408d50:	addss  %xmm4,%xmm5
  408d54:	add    $0x20,%r10
  408d58:	movss  %xmm5,-0x20(%r10)
  408d5e:	addss  %xmm4,%xmm5
  408d62:	movss  %xmm5,-0x1c(%r10)
  408d68:	addss  %xmm4,%xmm5
  408d6c:	movss  %xmm5,-0x18(%r10)
  408d72:	addss  %xmm4,%xmm5
  408d76:	movss  %xmm5,-0x14(%r10)
  408d7c:	addss  %xmm4,%xmm5
  408d80:	movss  %xmm5,-0x10(%r10)
  408d86:	addss  %xmm4,%xmm5
  408d8a:	movss  %xmm5,-0xc(%r10)
  408d90:	addss  %xmm4,%xmm5
  408d94:	movss  %xmm5,-0x8(%r10)
  408d9a:	addss  %xmm4,%xmm5
  408d9e:	movss  %xmm5,-0x4(%r10)
  408da4:	cmp    %r10,%r9
  408da7:	jne    408d50 <Init_Opacity+0x1b0>
  408da9:	movaps %xmm3,0x23bdf0(%rip)        # 644ba0 <magnitude_opacity+0x120>
  408db0:	movabs $0x3f8000003f800000,%r11
  408dba:	mov    $0x644bc0,%ecx
  408dbf:	movaps %xmm3,0x23bdea(%rip)        # 644bb0 <magnitude_opacity+0x130>
  408dc6:	mov    %r11,0x23bdcb(%rip)        # 644b98 <magnitude_opacity+0x118>
  408dcd:	movaps %xmm3,(%rcx)
  408dd0:	add    $0x90,%rcx
  408dd7:	movaps %xmm3,-0x80(%rcx)
  408ddb:	movaps %xmm3,-0x70(%rcx)
  408ddf:	movaps %xmm3,-0x60(%rcx)
  408de3:	movaps %xmm3,-0x50(%rcx)
  408de7:	movaps %xmm3,-0x40(%rcx)
  408deb:	movaps %xmm3,-0x30(%rcx)
  408def:	movaps %xmm3,-0x20(%rcx)
  408df3:	movaps %xmm3,-0x10(%rcx)
  408df7:	cmp    $0x645160,%rcx
  408dfe:	jne    408dcd <Init_Opacity+0x22d>
  408e00:	movss  %xmm1,0x23c358(%rip)        # 645160 <magnitude_opacity+0x6e0>
  408e08:	retq   
  408e09:	nopl   0x0(%rax)

0000000000408e10 <Init_Lighting>:
  408e10:	movss  0xffe4(%rip),%xmm0        # 418dfc <__dso_handle+0x34>
  408e18:	movabs $0x3f07d9e63ec212b7,%rax
  408e22:	mov    %rax,0x23c397(%rip)        # 6451c0 <light>
  408e29:	movl   $0xbf4212b7,0x23c395(%rip)        # 6451c8 <light+0x8>
  408e33:	movss  %xmm0,0x23c35d(%rip)        # 645198 <depth_hither>
  408e3b:	movl   $0x41f00000,0x23c373(%rip)        # 6451b8 <ambient_color>
  408e45:	movl   $0x42c80000,0x23c329(%rip)        # 645178 <diffuse_color>
  408e4f:	movss  %xmm0,0x23b7e9(%rip)        # 644640 <depth_exponent>
  408e57:	movl   $0x43020000,0x23c393(%rip)        # 6451f4 <specular_color>
  408e61:	movl   $0x41200000,0x23bbf5(%rip)        # 644a60 <specular_exponent>
  408e6b:	movl   $0x3ecccccd,0x23b7cf(%rip)        # 644644 <depth_yon>
  408e75:	retq   
  408e76:	nopw   %cs:0x0(%rax,%rax,1)

0000000000408e80 <Init_Parallelization>:
  408e80:	sub    $0x8,%rsp
  408e84:	mov    $0x419668,%edi
  408e89:	movq   $0x4,0x23c34c(%rip)        # 6451e0 <block_xlen>
  408e94:	movq   $0x4,0x23c301(%rip)        # 6451a0 <block_ylen>
  408e9f:	callq  401110 <puts@plt>
  408ea4:	mov    $0x4196c8,%edi
  408ea9:	callq  401110 <puts@plt>
  408eae:	mov    $0x419730,%edi
  408eb3:	callq  401110 <puts@plt>
  408eb8:	mov    0x23b591(%rip),%rsi        # 644450 <num_nodes>
  408ebf:	mov    $0x419815,%edi
  408ec4:	xor    %eax,%eax
  408ec6:	callq  401170 <printf@plt>
  408ecb:	mov    0x23c2ce(%rip),%rdx        # 6451a0 <block_ylen>
  408ed2:	mov    0x23c307(%rip),%rsi        # 6451e0 <block_xlen>
  408ed9:	xor    %eax,%eax
  408edb:	mov    $0x419825,%edi
  408ee0:	callq  401170 <printf@plt>
  408ee5:	cmpw   $0x0,0x23c2cf(%rip)        # 6451bc <adaptive>
  408eed:	jne    408f68 <Init_Parallelization+0xe8>
  408eef:	mov    $0x41985a,%edi
  408ef4:	callq  401110 <puts@plt>
  408ef9:	mov    $0x419758,%edi
  408efe:	callq  401110 <puts@plt>
  408f03:	mov    $0x419877,%edi
  408f08:	callq  401110 <puts@plt>
  408f0d:	pxor   %xmm0,%xmm0
  408f11:	mov    $0x3,%esi
  408f16:	pxor   %xmm2,%xmm2
  408f1a:	mov    $0x419798,%edi
  408f1f:	pxor   %xmm1,%xmm1
  408f23:	mov    $0x3,%eax
  408f28:	cvtss2sd 0x23c278(%rip),%xmm0        # 6451a8 <angle>
  408f30:	cvtss2sd 0x23c278(%rip),%xmm2        # 6451b0 <angle+0x8>
  408f38:	cvtss2sd 0x23c26c(%rip),%xmm1        # 6451ac <angle+0x4>
  408f40:	callq  401170 <printf@plt>
  408f45:	mov    0x216259(%rip),%esi        # 61f1a4 <ROTATE_STEPS>
  408f4b:	mov    $0x4197d8,%edi
  408f50:	xor    %eax,%eax
  408f52:	callq  401170 <printf@plt>
  408f57:	mov    $0xa,%edi
  408f5c:	add    $0x8,%rsp
  408f60:	jmpq   4010c0 <putchar@plt>
  408f65:	nopl   (%rax)
  408f68:	mov    $0x419840,%edi
  408f6d:	callq  401110 <puts@plt>
  408f72:	jmp    408ef9 <Init_Parallelization+0x79>
  408f74:	xchg   %ax,%ax
  408f76:	nopw   %cs:0x0(%rax,%rax,1)

0000000000408f80 <Init_Options>:
  408f80:	sub    $0x8,%rsp
  408f84:	mov    $0x644660,%edi
  408f89:	mov    $0x2f,%ecx
  408f8e:	movss  0x108fa(%rip),%xmm2        # 419890 <__dso_handle+0xac8>
  408f96:	xor    %eax,%eax
  408f98:	rep stos %rax,%es:(%rdi)
  408f9b:	movaps %xmm2,%xmm0
  408f9e:	movl   $0x0,0x23b834(%rip)        # 6447dc <density_opacity+0x17c>
  408fa8:	movss  0xfe4c(%rip),%xmm1        # 418dfc <__dso_handle+0x34>
  408fb0:	movq   $0x0,0x23b50d(%rip)        # 6444c8 <norm_address>
  408fbb:	addss  %xmm2,%xmm0
  408fbf:	movss  %xmm1,0x23ba95(%rip)        # 644a5c <density_opacity+0x3fc>
  408fc7:	movq   $0x0,0x23b64e(%rip)        # 644620 <opc_address>
  408fd2:	movq   $0x0,0x23b5e3(%rip)        # 6445c0 <pyr_address>
  408fdd:	movb   $0x0,0x23c1d0(%rip)        # 6451b4 <background>
  408fe4:	mov    $0x6447ec,%edx
  408fe9:	movq   $0x60,0x23c1f4(%rip)        # 6451e8 <density_epsilon>
  408ff4:	movl   $0x0,(%rdi)
  408ffa:	movss  %xmm2,0x23b7de(%rip)        # 6447e0 <density_opacity+0x180>
  409002:	movq   $0x1,0x23c183(%rip)        # 645190 <magnitude_epsilon>
  40900d:	movss  %xmm0,0x23b7cf(%rip)        # 6447e4 <density_opacity+0x184>
  409015:	addss  %xmm2,%xmm0
  409019:	movss  %xmm0,0x23b7c7(%rip)        # 6447e8 <density_opacity+0x188>
  409021:	nopl   0x0(%rax)
  409028:	addss  %xmm2,%xmm0
  40902c:	add    $0x24,%rdx
  409030:	movss  %xmm0,-0x24(%rdx)
  409035:	addss  %xmm2,%xmm0
  409039:	movss  %xmm0,-0x20(%rdx)
  40903e:	addss  %xmm2,%xmm0
  409042:	movss  %xmm0,-0x1c(%rdx)
  409047:	addss  %xmm2,%xmm0
  40904b:	movss  %xmm0,-0x18(%rdx)
  409050:	addss  %xmm2,%xmm0
  409054:	movss  %xmm0,-0x14(%rdx)
  409059:	addss  %xmm2,%xmm0
  40905d:	movss  %xmm0,-0x10(%rdx)
  409062:	addss  %xmm2,%xmm0
  409066:	movss  %xmm0,-0xc(%rdx)
  40906b:	addss  %xmm2,%xmm0
  40906f:	movss  %xmm0,-0x8(%rdx)
  409074:	addss  %xmm2,%xmm0
  409078:	movss  %xmm0,-0x4(%rdx)
  40907d:	cmp    $0x64487c,%rdx
  409084:	jne    409028 <Init_Options+0xa8>
  409086:	movaps 0x10813(%rip),%xmm3        # 4198a0 <__dso_handle+0xad8>
  40908d:	mov    $0x6448a0,%esi
  409092:	movaps %xmm3,0x23b7e7(%rip)        # 644880 <density_opacity+0x220>
  409099:	movaps %xmm3,0x23b7f0(%rip)        # 644890 <density_opacity+0x230>
  4090a0:	movss  %xmm1,0x23b7d4(%rip)        # 64487c <density_opacity+0x21c>
  4090a8:	movaps %xmm3,(%rsi)
  4090ab:	add    $0x90,%rsi
  4090b2:	movaps %xmm3,-0x80(%rsi)
  4090b6:	movaps %xmm3,-0x70(%rsi)
  4090ba:	movaps %xmm3,-0x60(%rsi)
  4090be:	movaps %xmm3,-0x50(%rsi)
  4090c2:	movaps %xmm3,-0x40(%rsi)
  4090c6:	movaps %xmm3,-0x30(%rsi)
  4090ca:	movaps %xmm3,-0x20(%rsi)
  4090ce:	movaps %xmm3,-0x10(%rsi)
  4090d2:	cmp    $0x644a50,%rsi
  4090d9:	jne    4090a8 <Init_Options+0x128>
  4090db:	movss  0x107b1(%rip),%xmm4        # 419894 <__dso_handle+0xacc>
  4090e3:	movabs $0x3f8000003f800000,%r8
  4090ed:	movaps %xmm4,%xmm5
  4090f0:	movss  %xmm1,0x23c070(%rip)        # 645168 <magnitude_opacity+0x6e8>
  4090f8:	movss  %xmm4,0x23b984(%rip)        # 644a84 <magnitude_opacity+0x4>
  409100:	mov    %r8,0x23b949(%rip)        # 644a50 <density_opacity+0x3f0>
  409107:	movl   $0x3f800000,0x23b947(%rip)        # 644a58 <density_opacity+0x3f8>
  409111:	addss  %xmm4,%xmm5
  409115:	movl   $0x0,0x23b961(%rip)        # 644a80 <magnitude_opacity>
  40911f:	mov    $0x644b98,%r9d
  409125:	mov    $0x644a98,%r10d
  40912b:	movss  %xmm5,0x23b955(%rip)        # 644a88 <magnitude_opacity+0x8>
  409133:	addss  %xmm4,%xmm5
  409137:	movss  %xmm5,0x23b94d(%rip)        # 644a8c <magnitude_opacity+0xc>
  40913f:	addss  %xmm4,%xmm5
  409143:	movss  %xmm5,0x23b945(%rip)        # 644a90 <magnitude_opacity+0x10>
  40914b:	addss  %xmm4,%xmm5
  40914f:	movss  %xmm5,0x23b93d(%rip)        # 644a94 <magnitude_opacity+0x14>
  409157:	nopw   0x0(%rax,%rax,1)
  409160:	addss  %xmm4,%xmm5
  409164:	add    $0x20,%r10
  409168:	movss  %xmm5,-0x20(%r10)
  40916e:	addss  %xmm4,%xmm5
  409172:	movss  %xmm5,-0x1c(%r10)
  409178:	addss  %xmm4,%xmm5
  40917c:	movss  %xmm5,-0x18(%r10)
  409182:	addss  %xmm4,%xmm5
  409186:	movss  %xmm5,-0x14(%r10)
  40918c:	addss  %xmm4,%xmm5
  409190:	movss  %xmm5,-0x10(%r10)
  409196:	addss  %xmm4,%xmm5
  40919a:	movss  %xmm5,-0xc(%r10)
  4091a0:	addss  %xmm4,%xmm5
  4091a4:	movss  %xmm5,-0x8(%r10)
  4091aa:	addss  %xmm4,%xmm5
  4091ae:	movss  %xmm5,-0x4(%r10)
  4091b4:	cmp    %r10,%r9
  4091b7:	jne    409160 <Init_Options+0x1e0>
  4091b9:	movaps %xmm3,0x23b9e0(%rip)        # 644ba0 <magnitude_opacity+0x120>
  4091c0:	movabs $0x3f8000003f800000,%r11
  4091ca:	mov    $0x644bc0,%ecx
  4091cf:	movaps %xmm3,0x23b9da(%rip)        # 644bb0 <magnitude_opacity+0x130>
  4091d6:	mov    %r11,0x23b9bb(%rip)        # 644b98 <magnitude_opacity+0x118>
  4091dd:	movaps %xmm3,(%rcx)
  4091e0:	add    $0x90,%rcx
  4091e7:	movaps %xmm3,-0x80(%rcx)
  4091eb:	movaps %xmm3,-0x70(%rcx)
  4091ef:	movaps %xmm3,-0x60(%rcx)
  4091f3:	movaps %xmm3,-0x50(%rcx)
  4091f7:	movaps %xmm3,-0x40(%rcx)
  4091fb:	movaps %xmm3,-0x30(%rcx)
  4091ff:	movaps %xmm3,-0x20(%rcx)
  409203:	movaps %xmm3,-0x10(%rcx)
  409207:	cmp    $0x645160,%rcx
  40920e:	jne    4091dd <Init_Options+0x25d>
  409210:	movabs $0x3f07d9e63ec212b7,%rax
  40921a:	movabs $0xc210000042b40000,%rdi
  409224:	movss  %xmm1,0x23bf34(%rip)        # 645160 <magnitude_opacity+0x6e0>
  40922c:	mov    %rax,0x23bf8d(%rip)        # 6451c0 <light>
  409233:	movl   $0xbf4212b7,0x23bf8b(%rip)        # 6451c8 <light+0x8>
  40923d:	movss  %xmm1,0x23bf53(%rip)        # 645198 <depth_hither>
  409245:	movl   $0x41f00000,0x23bf69(%rip)        # 6451b8 <ambient_color>
  40924f:	movss  %xmm1,0x23b3e9(%rip)        # 644640 <depth_exponent>
  409257:	movl   $0x42c80000,0x23bf17(%rip)        # 645178 <diffuse_color>
  409261:	movl   $0x43020000,0x23bf89(%rip)        # 6451f4 <specular_color>
  40926b:	movl   $0x41200000,0x23b7eb(%rip)        # 644a60 <specular_exponent>
  409275:	movl   $0x3ecccccd,0x23b3c5(%rip)        # 644644 <depth_yon>
  40927f:	mov    %rdi,0x23bf22(%rip)        # 6451a8 <angle>
  409286:	movl   $0x0,0x23bf20(%rip)        # 6451b0 <angle+0x8>
  409290:	callq  408e80 <Init_Parallelization>
  409295:	movl   $0x0,0x23bf51(%rip)        # 6451f0 <opacity_epsilon>
  40929f:	movl   $0x3f733333,0x23bedf(%rip)        # 645188 <opacity_cutoff>
  4092a9:	movq   $0x4,0x23bebc(%rip)        # 645170 <highest_sampling_boxlen>
  4092b4:	movq   $0x1,0x23bf19(%rip)        # 6451d8 <lowest_volume_boxlen>
  4092bf:	movq   $0x10,0x23b37e(%rip)        # 644648 <volume_color_difference>
  4092ca:	movq   $0x5,0x23beab(%rip)        # 645180 <pyr_highest_level>
  4092d5:	movq   $0x2,0x23bef0(%rip)        # 6451d0 <pyr_lowest_level>
  4092e0:	add    $0x8,%rsp
  4092e4:	retq   
  4092e5:	nopw   %cs:0x0(%rax,%rax,1)
  4092ef:	nop

00000000004092f0 <Trace_Ray>:
  4092f0:	push   %r15
  4092f2:	push   %r14
  4092f4:	cvtsd2ss %xmm0,%xmm0
  4092f8:	push   %r13
  4092fa:	push   %r12
  4092fc:	cvtsd2ss %xmm1,%xmm1
  409300:	push   %rbp
  409301:	push   %rbx
  409302:	pxor   %xmm2,%xmm2
  409306:	sub    $0xc0,%rsp
  40930d:	pxor   %xmm14,%xmm14
  409312:	movss  0x238f46(%rip),%xmm7        # 642260 <invjacobian>
  40931a:	mov    %rdi,0x60(%rsp)
  40931f:	mulss  %xmm0,%xmm7
  409323:	cvtsi2ssq 0x240054(%rip),%xmm2        # 649380 <image_zlen>
  40932c:	movss  0x238f38(%rip),%xmm4        # 64226c <invjacobian+0xc>
  409334:	mulss  %xmm1,%xmm4
  409338:	movss  0x238f24(%rip),%xmm3        # 642264 <invjacobian+0x4>
  409340:	mulss  %xmm0,%xmm3
  409344:	movss  0x238f24(%rip),%xmm5        # 642270 <invjacobian+0x10>
  40934c:	addss  0x23ff4c(%rip),%xmm7        # 6492a0 <out_invvertex>
  409354:	mulss  0x238f0c(%rip),%xmm0        # 642268 <invjacobian+0x8>
  40935c:	mulss  %xmm1,%xmm5
  409360:	movss  0x238f13(%rip),%xmm10        # 64227c <invjacobian+0x1c>
  409369:	mulss  0x238f03(%rip),%xmm1        # 642274 <invjacobian+0x14>
  409371:	movss  %xmm10,-0x74(%rsp)
  409378:	addss  0x23ff24(%rip),%xmm3        # 6492a4 <out_invvertex+0x4>
  409380:	movaps %xmm7,%xmm8
  409384:	addss  0x23ff1c(%rip),%xmm0        # 6492a8 <out_invvertex+0x8>
  40938c:	mulss  %xmm2,%xmm10
  409391:	addss  %xmm4,%xmm8
  409396:	movss  0x238eda(%rip),%xmm4        # 642278 <invjacobian+0x18>
  40939e:	movaps %xmm4,%xmm9
  4093a2:	movss  %xmm4,-0x70(%rsp)
  4093a8:	addss  %xmm5,%xmm3
  4093ac:	mulss  %xmm2,%xmm9
  4093b1:	movss  %xmm8,-0x40(%rsp)
  4093b8:	addss  %xmm1,%xmm0
  4093bc:	movss  0x238ebc(%rip),%xmm1        # 642280 <invjacobian+0x20>
  4093c4:	movaps %xmm1,%xmm11
  4093c8:	movss  %xmm3,-0x48(%rsp)
  4093ce:	addss  %xmm8,%xmm9
  4093d3:	movss  %xmm1,-0x78(%rsp)
  4093d9:	mulss  %xmm2,%xmm11
  4093de:	addss  %xmm3,%xmm10
  4093e3:	movss  %xmm0,-0x3c(%rsp)
  4093e9:	movaps %xmm9,%xmm12
  4093ed:	addss  %xmm0,%xmm11
  4093f2:	subss  %xmm8,%xmm12
  4093f7:	ucomiss %xmm14,%xmm12
  4093fb:	movaps %xmm12,%xmm13
  4093ff:	ja     409409 <Trace_Ray+0x119>
  409401:	xorps  0xf9f7(%rip),%xmm13        # 418e00 <__dso_handle+0x38>
  409409:	pxor   %xmm7,%xmm7
  40940d:	movsd  0xf9fa(%rip),%xmm15        # 418e10 <__dso_handle+0x48>
  409416:	cvtss2sd %xmm13,%xmm7
  40941b:	ucomisd %xmm7,%xmm15
  409420:	ja     40a200 <Trace_Ray+0xf10>
  409426:	movswl 0x23b1e3(%rip),%eax        # 644610 <opc_len>
  40942d:	pxor   %xmm4,%xmm4
  409431:	pxor   %xmm0,%xmm0
  409435:	movss  -0x40(%rsp),%xmm8
  40943c:	pxor   %xmm9,%xmm9
  409441:	cvtss2sd %xmm8,%xmm4
  409446:	pxor   %xmm3,%xmm3
  40944a:	sub    $0x1,%eax
  40944d:	pxor   %xmm5,%xmm5
  409451:	cvtsi2ss %eax,%xmm0
  409455:	subsd  %xmm4,%xmm9
  40945a:	cvtss2sd %xmm12,%xmm3
  40945f:	pxor   %xmm6,%xmm6
  409463:	movss  0xf991(%rip),%xmm1        # 418dfc <__dso_handle+0x34>
  40946b:	movss  %xmm1,-0x44(%rsp)
  409471:	divsd  %xmm3,%xmm9
  409476:	subss  %xmm8,%xmm0
  40947b:	divss  %xmm12,%xmm0
  409480:	cvtsd2ss %xmm9,%xmm5
  409485:	movaps %xmm5,%xmm4
  409488:	maxss  %xmm0,%xmm5
  40948c:	minss  %xmm0,%xmm4
  409490:	movaps %xmm5,%xmm0
  409493:	maxss  %xmm6,%xmm4
  409497:	minss  %xmm1,%xmm0
  40949b:	movaps %xmm10,%xmm8
  40949f:	pxor   %xmm7,%xmm7
  4094a3:	subss  -0x48(%rsp),%xmm8
  4094aa:	ucomiss %xmm7,%xmm8
  4094ae:	movaps %xmm8,%xmm9
  4094b2:	jbe    40a2a0 <Trace_Ray+0xfb0>
  4094b8:	pxor   %xmm3,%xmm3
  4094bc:	cvtss2sd %xmm9,%xmm3
  4094c1:	ucomisd %xmm3,%xmm15
  4094c6:	ja     40a258 <Trace_Ray+0xf68>
  4094cc:	pxor   %xmm6,%xmm6
  4094d0:	movswl 0x23b13b(%rip),%ecx        # 644612 <opc_len+0x2>
  4094d7:	movss  -0x48(%rsp),%xmm10
  4094de:	pxor   %xmm1,%xmm1
  4094e2:	pxor   %xmm5,%xmm5
  4094e6:	cvtss2sd %xmm10,%xmm6
  4094eb:	pxor   %xmm12,%xmm12
  4094f0:	sub    $0x1,%ecx
  4094f3:	pxor   %xmm13,%xmm13
  4094f8:	subsd  %xmm6,%xmm1
  4094fc:	cvtsi2ss %ecx,%xmm5
  409500:	cvtss2sd %xmm8,%xmm12
  409505:	divsd  %xmm12,%xmm1
  40950a:	subss  %xmm10,%xmm5
  40950f:	divss  %xmm8,%xmm5
  409514:	cvtsd2ss %xmm1,%xmm13
  409519:	movaps %xmm13,%xmm14
  40951d:	maxss  %xmm5,%xmm13
  409522:	minss  %xmm5,%xmm14
  409527:	minss  %xmm0,%xmm13
  40952c:	maxss  %xmm4,%xmm14
  409531:	movaps %xmm13,%xmm0
  409535:	movaps %xmm14,%xmm4
  409539:	movaps %xmm11,%xmm10
  40953d:	pxor   %xmm1,%xmm1
  409541:	subss  -0x3c(%rsp),%xmm10
  409548:	ucomiss %xmm1,%xmm10
  40954c:	movaps %xmm10,%xmm6
  409550:	ja     409559 <Trace_Ray+0x269>
  409552:	xorps  0xf8a7(%rip),%xmm6        # 418e00 <__dso_handle+0x38>
  409559:	pxor   %xmm12,%xmm12
  40955e:	cvtss2sd %xmm6,%xmm12
  409563:	ucomisd %xmm12,%xmm15
  409568:	jbe    40a2c0 <Trace_Ray+0xfd0>
  40956e:	pxor   %xmm3,%xmm3
  409572:	ucomiss -0x3c(%rsp),%xmm3
  409577:	ja     40a350 <Trace_Ray+0x1060>
  40957d:	movswl 0x23b090(%rip),%edi        # 644614 <opc_len+0x4>
  409584:	pxor   %xmm10,%xmm10
  409589:	movss  -0x3c(%rsp),%xmm6
  40958f:	sub    $0x1,%edi
  409592:	cvtsi2ss %edi,%xmm10
  409597:	ucomiss %xmm10,%xmm6
  40959b:	jbe    4095b0 <Trace_Ray+0x2c0>
  40959d:	ucomiss %xmm10,%xmm11
  4095a1:	ja     40a240 <Trace_Ray+0xf50>
  4095a7:	nopw   0x0(%rax,%rax,1)
  4095b0:	mulss  %xmm2,%xmm4
  4095b4:	pxor   %xmm1,%xmm1
  4095b8:	cvttss2si %xmm4,%rbp
  4095bd:	cvtsi2ss %rbp,%xmm1
  4095c2:	ucomiss %xmm1,%xmm4
  4095c5:	jp     4095c9 <Trace_Ray+0x2d9>
  4095c7:	je     4095cd <Trace_Ray+0x2dd>
  4095c9:	add    $0x1,%rbp
  4095cd:	mulss  %xmm0,%xmm2
  4095d1:	cvttss2si %xmm2,%r8
  4095d6:	cmp    %r8,%rbp
  4095d9:	mov    %r8,-0x38(%rsp)
  4095de:	jg     40a240 <Trace_Ray+0xf50>
  4095e4:	pxor   %xmm0,%xmm0
  4095e8:	movss  -0x70(%rsp),%xmm2
  4095ee:	movaps %xmm2,%xmm3
  4095f1:	movss  -0x74(%rsp),%xmm11
  4095f8:	pxor   %xmm14,%xmm14
  4095fd:	cvtsi2ss %rbp,%xmm0
  409602:	movss  -0x78(%rsp),%xmm13
  409609:	ucomiss %xmm14,%xmm2
  40960d:	pxor   %xmm5,%xmm5
  409611:	mulss  %xmm0,%xmm3
  409615:	mulss  %xmm0,%xmm11
  40961a:	mulss  %xmm0,%xmm13
  40961f:	addss  -0x40(%rsp),%xmm3
  409625:	addss  -0x48(%rsp),%xmm11
  40962c:	addss  -0x3c(%rsp),%xmm13
  409633:	movss  %xmm3,-0x54(%rsp)
  409639:	movss  %xmm11,-0x68(%rsp)
  409640:	movss  %xmm13,-0x6c(%rsp)
  409647:	cvtss2sd %xmm3,%xmm5
  40964b:	jbe    40a360 <Trace_Ray+0x1070>
  409651:	addsd  %xmm15,%xmm5
  409656:	cvttsd2si %xmm5,%r8
  40965b:	movss  -0x74(%rsp),%xmm7
  409661:	pxor   %xmm8,%xmm8
  409666:	ucomiss %xmm14,%xmm7
  40966a:	cvtss2sd -0x68(%rsp),%xmm8
  409671:	jbe    40a920 <Trace_Ray+0x1630>
  409677:	addsd  %xmm15,%xmm8
  40967c:	movaps %xmm14,%xmm3
  409680:	cvttsd2si %xmm8,%r11
  409685:	movss  -0x78(%rsp),%xmm4
  40968b:	pxor   %xmm9,%xmm9
  409690:	ucomiss %xmm3,%xmm4
  409693:	cvtss2sd -0x6c(%rsp),%xmm9
  40969a:	jbe    40a938 <Trace_Ray+0x1648>
  4096a0:	addsd  %xmm15,%xmm9
  4096a5:	cvttsd2si %xmm9,%r10
  4096aa:	mov    %r10,-0x60(%rsp)
  4096af:	movswl 0x23aef1(%rip),%r12d        # 6445a8 <pyr_levels>
  4096b7:	mov    0x23bac2(%rip),%r13        # 645180 <pyr_highest_level>
  4096be:	movswq 0x23ae3c(%rip),%r15        # 644502 <pyr_len+0x2>
  4096c6:	movswq 0x23ae32(%rip),%rax        # 644500 <pyr_len>
  4096ce:	movswq 0x23af3c(%rip),%rcx        # 644612 <opc_len+0x2>
  4096d6:	movswq 0x23af32(%rip),%rsi        # 644610 <opc_len>
  4096de:	movswq 0x23adf0(%rip),%rbp        # 6444d6 <norm_len+0x2>
  4096e6:	movswq 0x23ade6(%rip),%r9        # 6444d4 <norm_len>
  4096ee:	sub    $0x1,%r12d
  4096f2:	mov    0x23bad7(%rip),%r14        # 6451d0 <pyr_lowest_level>
  4096f9:	mov    0x23af20(%rip),%rdx        # 644620 <opc_address>
  409700:	movslq %r12d,%rbx
  409703:	mov    0x23adbe(%rip),%rdi        # 6444c8 <norm_address>
  40970a:	mov    %r15,0x98(%rsp)
  409712:	cmp    %r13,%rbx
  409715:	movss  0x238b1a(%rip),%xmm10        # 642238 <invinvjacobian+0x18>
  40971e:	cmovg  %r13,%rbx
  409722:	movss  0x238b12(%rip),%xmm6        # 64223c <invinvjacobian+0x1c>
  40972a:	movss  0x238b0e(%rip),%xmm1        # 642240 <invinvjacobian+0x20>
  409732:	mov    %r14,0x58(%rsp)
  409737:	movss  0x23fbd1(%rip),%xmm2        # 649310 <in_max>
  40973f:	mov    %rax,0xa0(%rsp)
  409747:	movss  0x23fbc4(%rip),%xmm12        # 649314 <in_max+0x4>
  409750:	mov    %rdx,-0x10(%rsp)
  409755:	movss  0x23fbba(%rip),%xmm11        # 649318 <in_max+0x8>
  40975e:	mov    %rcx,-0x8(%rsp)
  409763:	mov    %rsi,(%rsp)
  409767:	mov    %rdi,0xa8(%rsp)
  40976f:	movss  %xmm10,0x40(%rsp)
  409776:	mov    %rbp,0x8(%rsp)
  40977b:	movss  %xmm6,0x44(%rsp)
  409781:	mov    0x23ae38(%rip),%r13        # 6445c0 <pyr_address>
  409788:	movss  %xmm1,0x78(%rsp)
  40978e:	lea    (%rbx,%rbx,2),%rcx
  409792:	movss  %xmm2,-0x18(%rsp)
  409798:	pxor   %xmm5,%xmm5
  40979c:	movss  %xmm12,-0x14(%rsp)
  4097a3:	pxor   %xmm14,%xmm14
  4097a8:	movss  %xmm11,0x28(%rsp)
  4097af:	mov    %r9,0x10(%rsp)
  4097b4:	add    %rcx,%rcx
  4097b7:	mov    0x23fb42(%rip),%r12        # 649300 <opc_xlen>
  4097be:	pxor   %xmm8,%xmm8
  4097c3:	mov    0x23ba56(%rip),%r14        # 645220 <norm_xlen>
  4097ca:	lea    0x644500(%rcx),%rdi
  4097d1:	cvtss2sd -0x70(%rsp),%xmm5
  4097d7:	mov    0x23fb92(%rip),%rax        # 649370 <norm_xylen>
  4097de:	pxor   %xmm9,%xmm9
  4097e3:	mov    %r12,0xb0(%rsp)
  4097eb:	sub    $0x1,%r12
  4097ef:	mov    0x6445c0(,%rbx,8),%rsi
  4097f7:	add    %r14,%r14
  4097fa:	mov    0x23ba27(%rip),%r15        # 645228 <opc_xylen>
  409801:	mov    %r12,0x30(%rsp)
  409806:	cvtss2sd -0x74(%rsp),%xmm14
  40980d:	movswq 0x644502(%rcx),%r12
  409815:	movswq 0x644500(%rcx),%rbp
  40981d:	cvtss2sd -0x78(%rsp),%xmm8
  409824:	lea    -0x2(%r14),%rdx
  409828:	mov    %rdi,0x50(%rsp)
  40982d:	movss  0x23b952(%rip),%xmm13        # 645188 <opacity_cutoff>
  409836:	mov    0x238a93(%rip),%r10        # 6422d0 <shd_address>
  40983d:	mov    -0x60(%rsp),%rdi
  409842:	add    %rax,%rax
  409845:	movss  %xmm13,0x2c(%rsp)
  40984c:	movsd  %xmm5,-0x30(%rsp)
  409852:	mov    %rsi,0x48(%rsp)
  409857:	mov    %rsi,-0x50(%rsp)
  40985c:	movsd  %xmm14,-0x28(%rsp)
  409863:	mov    %r14,0xb8(%rsp)
  40986b:	mov    %rbx,%rsi
  40986e:	movsd  %xmm8,-0x20(%rsp)
  409875:	mov    %r15,0x18(%rsp)
  40987a:	movss  %xmm9,-0x58(%rsp)
  409881:	mov    %rax,0x20(%rsp)
  409886:	mov    %rdx,0x38(%rsp)
  40988b:	nopl   0x0(%rax,%rax,1)
  409890:	mov    %esi,%ecx
  409892:	mov    %r11,%r14
  409895:	mov    %r8,%rdx
  409898:	sar    %cl,%rdi
  40989b:	sar    %cl,%r14
  40989e:	sar    %cl,%rdx
  4098a1:	imul   %r12,%rdi
  4098a5:	mov    %r14,%r15
  4098a8:	mov    %rdx,%rcx
  4098ab:	mov    -0x50(%rsp),%r14
  4098b0:	mov    %esi,%r9d
  4098b3:	add    %rdi,%r15
  4098b6:	mov    %r15,%rax
  4098b9:	imul   %rbp,%rax
  4098bd:	add    %rax,%rcx
  4098c0:	mov    %rcx,%rdi
  4098c3:	and    $0x7,%ecx
  4098c6:	sar    $0x3,%rdi
  4098ca:	movzbl (%r14,%rdi,1),%r15d
  4098cf:	sar    %cl,%r15d
  4098d2:	and    $0x1,%r15w
  4098d7:	je     4098e4 <Trace_Ray+0x5f4>
  4098d9:	cmp    %rsi,0x58(%rsp)
  4098de:	jl     40a720 <Trace_Ray+0x1430>
  4098e4:	movsd  -0x30(%rsp),%xmm7
  4098ea:	ucomisd %xmm15,%xmm7
  4098ef:	jbe    40a480 <Trace_Ray+0x1190>
  4098f5:	movss  -0x54(%rsp),%xmm6
  4098fb:	lea    (%rsi,%rsi,2),%rdx
  4098ff:	mov    %r9d,%ecx
  409902:	cvttss2si %xmm6,%rax
  409907:	movswq 0x644540(%rdx,%rdx,1),%rdi
  409910:	pxor   %xmm11,%xmm11
  409915:	sar    %cl,%rax
  409918:	add    $0x1,%rax
  40991c:	imul   %rdi,%rax
  409920:	cvtsi2ss %rax,%xmm11
  409925:	subss  %xmm6,%xmm11
  40992a:	mulss  0x40(%rsp),%xmm11
  409931:	ucomiss 0xff77(%rip),%xmm11        # 4198b0 <__dso_handle+0xae8>
  409939:	jbe    409944 <Trace_Ray+0x654>
  40993b:	movss  0xff6c(%rip),%xmm11        # 4198b0 <__dso_handle+0xae8>
  409944:	movsd  -0x28(%rsp),%xmm1
  40994a:	ucomisd %xmm15,%xmm1
  40994f:	jbe    40a410 <Trace_Ray+0x1120>
  409955:	movss  -0x68(%rsp),%xmm14
  40995c:	lea    (%rsi,%rsi,2),%rax
  409960:	mov    %r9d,%ecx
  409963:	cvttss2si %xmm14,%r14
  409968:	movswq 0x644542(%rax,%rax,1),%rdx
  409971:	pxor   %xmm8,%xmm8
  409976:	sar    %cl,%r14
  409979:	add    $0x1,%r14
  40997d:	imul   %rdx,%r14
  409981:	cvtsi2ss %r14,%xmm8
  409986:	subss  %xmm14,%xmm8
  40998b:	mulss  0x44(%rsp),%xmm8
  409992:	minss  %xmm8,%xmm11
  409997:	movsd  -0x20(%rsp),%xmm7
  40999d:	ucomisd %xmm15,%xmm7
  4099a2:	jbe    40a3a0 <Trace_Ray+0x10b0>
  4099a8:	movss  -0x6c(%rsp),%xmm2
  4099ae:	lea    (%rsi,%rsi,2),%rdi
  4099b2:	mov    %r9d,%ecx
  4099b5:	cvttss2si %xmm2,%rdx
  4099ba:	movswq 0x644544(%rdi,%rdi,1),%r14
  4099c3:	pxor   %xmm1,%xmm1
  4099c7:	sar    %cl,%rdx
  4099ca:	add    $0x1,%rdx
  4099ce:	imul   %r14,%rdx
  4099d2:	cvtsi2ss %rdx,%xmm1
  4099d7:	subss  %xmm2,%xmm1
  4099db:	mulss  0x78(%rsp),%xmm1
  4099e1:	minss  %xmm1,%xmm11
  4099e6:	movaps %xmm0,%xmm12
  4099ea:	test   %r15w,%r15w
  4099ee:	addss  %xmm11,%xmm12
  4099f3:	movss  %xmm12,-0x64(%rsp)
  4099fa:	je     409ea9 <Trace_Ray+0xbb9>
  409a00:	cvttss2si %xmm0,%r9
  409a05:	pxor   %xmm13,%xmm13
  409a0a:	cvtsi2ss %r9,%xmm13
  409a0f:	ucomiss %xmm0,%xmm13
  409a13:	jp     409a17 <Trace_Ray+0x727>
  409a15:	je     409a1b <Trace_Ray+0x72b>
  409a17:	add    $0x1,%r9
  409a1b:	mov    -0x38(%rsp),%r15
  409a20:	cvttss2si -0x64(%rsp),%r14
  409a27:	cmp    %r15,%r14
  409a2a:	cmovg  %r15,%r14
  409a2e:	cmp    %r14,%r9
  409a31:	jg     409ea9 <Trace_Ray+0xbb9>
  409a37:	pxor   %xmm12,%xmm12
  409a3c:	movss  -0x70(%rsp),%xmm14
  409a43:	movss  -0x74(%rsp),%xmm13
  409a4a:	mov    %r11,0x68(%rsp)
  409a4f:	mov    %r8,0x70(%rsp)
  409a54:	mov    %rbx,0x80(%rsp)
  409a5c:	movss  %xmm11,0x7c(%rsp)
  409a63:	cvtsi2ss %r9,%xmm12
  409a68:	mov    %rsi,0x88(%rsp)
  409a70:	mov    %rbp,0x90(%rsp)
  409a78:	mov    0xa0(%rsp),%r8
  409a80:	mov    0xa8(%rsp),%r11
  409a88:	mov    0xb0(%rsp),%rbx
  409a90:	mov    0x98(%rsp),%rsi
  409a98:	mov    0xb8(%rsp),%rbp
  409aa0:	movaps %xmm9,%xmm11
  409aa4:	mulss  %xmm12,%xmm14
  409aa9:	mulss  %xmm12,%xmm13
  409aae:	mulss  -0x78(%rsp),%xmm12
  409ab5:	addss  -0x40(%rsp),%xmm14
  409abc:	addss  -0x48(%rsp),%xmm13
  409ac3:	addss  -0x3c(%rsp),%xmm12
  409aca:	nopw   0x0(%rax,%rax,1)
  409ad0:	cvttss2si %xmm12,%rdx
  409ad5:	mov    %rsi,%rax
  409ad8:	cvttss2si %xmm13,%rdi
  409add:	cvttss2si %xmm14,%rcx
  409ae2:	imul   %rdx,%rax
  409ae6:	add    %rdi,%rax
  409ae9:	imul   %r8,%rax
  409aed:	add    %rcx,%rax
  409af0:	mov    %rax,%r15
  409af3:	and    $0x7,%eax
  409af6:	sar    $0x3,%r15
  409afa:	movzbl 0x0(%r13,%r15,1),%r15d
  409b00:	bt     %eax,%r15d
  409b04:	jae    409e5a <Trace_Ray+0xb6a>
  409b0a:	movss  -0x18(%rsp),%xmm9
  409b11:	movaps %xmm14,%xmm0
  409b15:	ucomiss %xmm14,%xmm9
  409b19:	ja     409b24 <Trace_Ray+0x834>
  409b1b:	cvttss2si %xmm9,%rcx
  409b20:	movaps %xmm9,%xmm0
  409b24:	movss  -0x14(%rsp),%xmm5
  409b2a:	ucomiss %xmm13,%xmm5
  409b2e:	movaps %xmm13,%xmm9
  409b32:	ja     409b3d <Trace_Ray+0x84d>
  409b34:	cvttss2si %xmm5,%rdi
  409b39:	movaps %xmm5,%xmm9
  409b3d:	movss  0x28(%rsp),%xmm8
  409b44:	ucomiss %xmm12,%xmm8
  409b48:	movaps %xmm12,%xmm4
  409b4c:	ja     409b57 <Trace_Ray+0x867>
  409b4e:	cvttss2si %xmm8,%rdx
  409b53:	movaps %xmm8,%xmm4
  409b57:	mov    -0x8(%rsp),%r15
  409b5c:	pxor   %xmm3,%xmm3
  409b60:	pxor   %xmm7,%xmm7
  409b64:	pxor   %xmm10,%xmm10
  409b69:	movss  -0x44(%rsp),%xmm8
  409b70:	imul   %rdx,%r15
  409b74:	movaps %xmm8,%xmm5
  409b78:	cvtsi2ss %rdi,%xmm3
  409b7d:	cvtsi2ss %rcx,%xmm7
  409b82:	add    %rdi,%r15
  409b85:	add    $0x1,%rcx
  409b89:	imul   (%rsp),%r15
  409b8e:	cvtsi2ss %rdx,%xmm10
  409b93:	imul   0x8(%rsp),%rdx
  409b99:	pxor   %xmm2,%xmm2
  409b9d:	movaps %xmm8,%xmm1
  409ba1:	add    %rcx,%r15
  409ba4:	add    -0x10(%rsp),%r15
  409ba9:	add    %rdi,%rdx
  409bac:	imul   0x10(%rsp),%rdx
  409bb2:	subss  %xmm3,%xmm9
  409bb7:	movzbl (%r15),%eax
  409bbb:	pxor   %xmm3,%xmm3
  409bbf:	subss  %xmm7,%xmm0
  409bc3:	subss  %xmm9,%xmm5
  409bc8:	cvtsi2ss %eax,%xmm3
  409bcc:	add    %rdx,%rcx
  409bcf:	lea    -0x1(%r15),%rdx
  409bd3:	movzbl -0x1(%r15),%r15d
  409bd8:	subss  %xmm10,%xmm4
  409bdd:	movaps %xmm0,%xmm10
  409be1:	subss  %xmm0,%xmm1
  409be5:	lea    (%r11,%rcx,2),%rcx
  409be9:	mulss  %xmm9,%xmm0
  409bee:	mulss  %xmm5,%xmm10
  409bf3:	cvtsi2ss %r15d,%xmm2
  409bf8:	movswq (%rcx),%rdi
  409bfc:	lea    -0x2(%rcx),%rax
  409c00:	movswq -0x2(%rcx),%rcx
  409c05:	subss  %xmm4,%xmm8
  409c0a:	mulss  %xmm1,%xmm5
  409c0e:	movaps %xmm10,%xmm6
  409c12:	mulss  %xmm9,%xmm1
  409c17:	pxor   %xmm9,%xmm9
  409c1c:	movzbl (%r10,%rdi,1),%edi
  409c21:	mulss  %xmm4,%xmm10
  409c26:	mulss  %xmm8,%xmm6
  409c2b:	movaps %xmm5,%xmm7
  409c2e:	mulss  %xmm4,%xmm5
  409c32:	mulss  %xmm8,%xmm7
  409c37:	mulss  %xmm6,%xmm3
  409c3b:	pxor   %xmm6,%xmm6
  409c3f:	cvtsi2ss %edi,%xmm6
  409c43:	movzbl (%r10,%rcx,1),%edi
  409c48:	lea    (%rax,%rbp,1),%rcx
  409c4c:	add    0x20(%rsp),%rax
  409c51:	mulss  %xmm7,%xmm2
  409c55:	pxor   %xmm7,%xmm7
  409c59:	cvtsi2ss %edi,%xmm7
  409c5d:	lea    (%rdx,%rbx,1),%rdi
  409c61:	add    0x18(%rsp),%rdx
  409c66:	movzbl (%rdi),%r15d
  409c6a:	movzbl -0x1(%rdi),%edi
  409c6e:	cvtsi2ss %edi,%xmm9
  409c73:	movzbl (%rdx),%edi
  409c76:	mulss  %xmm3,%xmm6
  409c7a:	addss  %xmm2,%xmm3
  409c7e:	mulss  %xmm2,%xmm7
  409c82:	pxor   %xmm2,%xmm2
  409c86:	cvtsi2ss %r15d,%xmm2
  409c8b:	movswq (%rcx),%r15
  409c8f:	movswq -0x2(%rcx),%rcx
  409c94:	addss  %xmm6,%xmm7
  409c98:	movaps %xmm0,%xmm6
  409c9b:	mulss  %xmm4,%xmm0
  409c9f:	mulss  %xmm8,%xmm6
  409ca4:	movzbl (%r10,%r15,1),%r15d
  409ca9:	mulss  %xmm1,%xmm8
  409cae:	mulss  %xmm4,%xmm1
  409cb2:	pxor   %xmm4,%xmm4
  409cb6:	mulss  %xmm9,%xmm8
  409cbb:	pxor   %xmm9,%xmm9
  409cc0:	mulss  %xmm6,%xmm2
  409cc4:	pxor   %xmm6,%xmm6
  409cc8:	cvtsi2ss %r15d,%xmm6
  409ccd:	movzbl (%r10,%rcx,1),%r15d
  409cd2:	movswq (%rax),%rcx
  409cd6:	mulss  %xmm2,%xmm6
  409cda:	addss  %xmm3,%xmm2
  409cde:	pxor   %xmm3,%xmm3
  409ce2:	cvtsi2ss %r15d,%xmm3
  409ce7:	movzbl (%r10,%rcx,1),%r15d
  409cec:	movswq -0x2(%rax),%rcx
  409cf1:	addss  %xmm8,%xmm2
  409cf6:	add    0x38(%rsp),%rax
  409cfb:	addss  %xmm7,%xmm6
  409cff:	pxor   %xmm7,%xmm7
  409d03:	cvtsi2ss %r15d,%xmm7
  409d08:	movzbl (%r10,%rcx,1),%r15d
  409d0d:	movswq (%rax),%rcx
  409d11:	cvtsi2ss %r15d,%xmm9
  409d16:	movzbl (%r10,%rcx,1),%r15d
  409d1b:	mulss  %xmm8,%xmm3
  409d20:	pxor   %xmm8,%xmm8
  409d25:	cvtsi2ss %edi,%xmm8
  409d2a:	movzbl -0x1(%rdx),%edi
  409d2e:	add    0x30(%rsp),%rdx
  409d33:	addss  %xmm3,%xmm6
  409d37:	pxor   %xmm3,%xmm3
  409d3b:	cvtsi2ss %r15d,%xmm3
  409d40:	mulss  %xmm8,%xmm10
  409d45:	pxor   %xmm8,%xmm8
  409d4a:	mulss  %xmm10,%xmm7
  409d4f:	addss  %xmm10,%xmm2
  409d54:	pxor   %xmm10,%xmm10
  409d59:	cvtsi2ss %edi,%xmm10
  409d5e:	movzbl (%rdx),%edi
  409d61:	movzbl -0x1(%rdx),%edx
  409d65:	movswq -0x2(%rax),%rax
  409d6a:	addss  %xmm7,%xmm6
  409d6e:	pxor   %xmm7,%xmm7
  409d72:	cvtss2sd %xmm11,%xmm7
  409d77:	mulss  %xmm10,%xmm5
  409d7c:	pxor   %xmm10,%xmm10
  409d81:	mulss  %xmm5,%xmm9
  409d86:	addss  %xmm5,%xmm2
  409d8a:	pxor   %xmm5,%xmm5
  409d8e:	cvtsi2ss %edi,%xmm5
  409d92:	movzbl (%r10,%rax,1),%edi
  409d97:	addss  %xmm9,%xmm6
  409d9c:	pxor   %xmm9,%xmm9
  409da1:	cvtsi2ss %edi,%xmm4
  409da5:	cvtss2sd -0x58(%rsp),%xmm9
  409dac:	mulss  %xmm5,%xmm0
  409db0:	pxor   %xmm5,%xmm5
  409db4:	mulss  %xmm0,%xmm3
  409db8:	addss  %xmm0,%xmm2
  409dbc:	pxor   %xmm0,%xmm0
  409dc0:	cvtsi2ss %edx,%xmm0
  409dc4:	addss  %xmm3,%xmm6
  409dc8:	pxor   %xmm3,%xmm3
  409dcc:	mulss  %xmm1,%xmm0
  409dd0:	pxor   %xmm1,%xmm1
  409dd4:	mulss  %xmm0,%xmm4
  409dd8:	addss  %xmm2,%xmm0
  409ddc:	pxor   %xmm2,%xmm2
  409de0:	addss  %xmm4,%xmm6
  409de4:	cvtss2sd %xmm0,%xmm2
  409de8:	pxor   %xmm0,%xmm0
  409dec:	mulsd  0xfad4(%rip),%xmm2        # 4198c8 <__dso_handle+0xb00>
  409df4:	pxor   %xmm4,%xmm4
  409df8:	cvtss2sd %xmm6,%xmm1
  409dfc:	movsd  0xfacc(%rip),%xmm6        # 4198d0 <__dso_handle+0xb08>
  409e04:	mulsd  0xfabc(%rip),%xmm1        # 4198c8 <__dso_handle+0xb00>
  409e0c:	subsd  %xmm7,%xmm6
  409e10:	cvtsd2ss %xmm2,%xmm3
  409e14:	cvtsd2ss %xmm1,%xmm8
  409e19:	cvtss2sd %xmm3,%xmm0
  409e1d:	mulss  0x645240(,%r9,4),%xmm8
  409e27:	cvtss2sd %xmm8,%xmm10
  409e2c:	mulsd  %xmm6,%xmm10
  409e31:	mulsd  %xmm0,%xmm6
  409e35:	addsd  %xmm9,%xmm10
  409e3a:	cvtsd2ss %xmm6,%xmm4
  409e3e:	cvtsd2ss %xmm10,%xmm5
  409e43:	addss  %xmm4,%xmm11
  409e48:	movss  %xmm5,-0x58(%rsp)
  409e4e:	ucomiss 0x2c(%rsp),%xmm11
  409e54:	ja     40a800 <Trace_Ray+0x1510>
  409e5a:	add    $0x1,%r9
  409e5e:	addss  -0x70(%rsp),%xmm14
  409e65:	cmp    %r9,%r14
  409e68:	addss  -0x74(%rsp),%xmm13
  409e6f:	addss  -0x78(%rsp),%xmm12
  409e76:	jge    409ad0 <Trace_Ray+0x7e0>
  409e7c:	mov    0x68(%rsp),%r11
  409e81:	mov    0x70(%rsp),%r8
  409e86:	mov    0x80(%rsp),%rbx
  409e8e:	mov    0x88(%rsp),%rsi
  409e96:	mov    0x90(%rsp),%rbp
  409e9e:	movaps %xmm11,%xmm9
  409ea2:	movss  0x7c(%rsp),%xmm11
  409ea9:	pxor   %xmm12,%xmm12
  409eae:	movss  -0x64(%rsp),%xmm14
  409eb5:	cvtsi2ssq -0x38(%rsp),%xmm12
  409ebc:	ucomiss %xmm12,%xmm14
  409ec0:	jae    40a8b0 <Trace_Ray+0x15c0>
  409ec6:	movss  -0x70(%rsp),%xmm13
  409ecd:	pxor   %xmm10,%xmm10
  409ed2:	movaps %xmm13,%xmm1
  409ed6:	movss  -0x74(%rsp),%xmm7
  409edc:	pxor   %xmm6,%xmm6
  409ee0:	mulss  %xmm11,%xmm1
  409ee5:	movss  -0x54(%rsp),%xmm8
  409eec:	mulss  %xmm11,%xmm7
  409ef1:	mulss  -0x78(%rsp),%xmm11
  409ef8:	ucomiss %xmm10,%xmm13
  409efc:	addss  %xmm1,%xmm8
  409f01:	addss  -0x68(%rsp),%xmm7
  409f07:	addss  -0x6c(%rsp),%xmm11
  409f0e:	movss  %xmm8,-0x54(%rsp)
  409f15:	cvtss2sd %xmm8,%xmm6
  409f1a:	movss  %xmm7,-0x68(%rsp)
  409f20:	movss  %xmm11,-0x6c(%rsp)
  409f27:	jbe    40a6d0 <Trace_Ray+0x13e0>
  409f2d:	addsd  %xmm15,%xmm6
  409f32:	movaps %xmm10,%xmm1
  409f36:	cvttsd2si %xmm6,%r15
  409f3b:	movss  -0x74(%rsp),%xmm2
  409f41:	pxor   %xmm5,%xmm5
  409f45:	ucomiss %xmm1,%xmm2
  409f48:	cvtss2sd -0x68(%rsp),%xmm5
  409f4e:	jbe    40a6b8 <Trace_Ray+0x13c8>
  409f54:	addsd  %xmm15,%xmm5
  409f59:	movaps %xmm1,%xmm7
  409f5c:	cvttsd2si %xmm5,%rdx
  409f61:	movss  -0x78(%rsp),%xmm0
  409f67:	pxor   %xmm3,%xmm3
  409f6b:	ucomiss %xmm7,%xmm0
  409f6e:	cvtss2sd -0x6c(%rsp),%xmm3
  409f74:	jbe    40a688 <Trace_Ray+0x1398>
  409f7a:	addsd  %xmm15,%xmm3
  409f7f:	cmp    %rbx,%rsi
  409f82:	cvttsd2si %xmm3,%rdi
  409f87:	jge    40a69b <Trace_Ray+0x13ab>
  409f8d:	mov    %rbx,%r12
  409f90:	sub    %rsi,%r12
  409f93:	and    $0x7,%r12d
  409f97:	je     40a175 <Trace_Ray+0xe85>
  409f9d:	cmp    $0x1,%r12
  409fa1:	je     40a075 <Trace_Ray+0xd85>
  409fa7:	cmp    $0x2,%r12
  409fab:	je     40a059 <Trace_Ray+0xd69>
  409fb1:	cmp    $0x3,%r12
  409fb5:	je     40a03d <Trace_Ray+0xd4d>
  409fbb:	cmp    $0x4,%r12
  409fbf:	je     40a021 <Trace_Ray+0xd31>
  409fc1:	cmp    $0x5,%r12
  409fc5:	je     40a005 <Trace_Ray+0xd15>
  409fc7:	cmp    $0x6,%r12
  409fcb:	je     409fe9 <Trace_Ray+0xcf9>
  409fcd:	lea    0x1(%rsi),%ecx
  409fd0:	mov    %r15,%r9
  409fd3:	mov    %r8,%r14
  409fd6:	sar    %cl,%r9
  409fd9:	sar    %cl,%r14
  409fdc:	cmp    %r14,%r9
  409fdf:	je     40a950 <Trace_Ray+0x1660>
  409fe5:	add    $0x1,%rsi
  409fe9:	lea    0x1(%rsi),%ecx
  409fec:	mov    %r15,%r14
  409fef:	mov    %r8,%rax
  409ff2:	sar    %cl,%r14
  409ff5:	sar    %cl,%rax
  409ff8:	cmp    %rax,%r14
  409ffb:	je     40a8d0 <Trace_Ray+0x15e0>
  40a001:	add    $0x1,%rsi
  40a005:	lea    0x1(%rsi),%ecx
  40a008:	mov    %r15,%rax
  40a00b:	mov    %r8,%r12
  40a00e:	sar    %cl,%rax
  40a011:	sar    %cl,%r12
  40a014:	cmp    %r12,%rax
  40a017:	je     40a850 <Trace_Ray+0x1560>
  40a01d:	add    $0x1,%rsi
  40a021:	lea    0x1(%rsi),%ecx
  40a024:	mov    %r15,%r12
  40a027:	mov    %r8,%r9
  40a02a:	sar    %cl,%r12
  40a02d:	sar    %cl,%r9
  40a030:	cmp    %r9,%r12
  40a033:	je     40a7c8 <Trace_Ray+0x14d8>
  40a039:	add    $0x1,%rsi
  40a03d:	lea    0x1(%rsi),%ecx
  40a040:	mov    %r15,%r9
  40a043:	mov    %r8,%rax
  40a046:	sar    %cl,%r9
  40a049:	sar    %cl,%rax
  40a04c:	cmp    %rax,%r9
  40a04f:	je     40a790 <Trace_Ray+0x14a0>
  40a055:	add    $0x1,%rsi
  40a059:	lea    0x1(%rsi),%ecx
  40a05c:	mov    %r15,%rax
  40a05f:	mov    %r8,%r12
  40a062:	sar    %cl,%rax
  40a065:	sar    %cl,%r12
  40a068:	cmp    %r12,%rax
  40a06b:	je     40a758 <Trace_Ray+0x1468>
  40a071:	add    $0x1,%rsi
  40a075:	lea    0x1(%rsi),%ecx
  40a078:	mov    %r15,%r12
  40a07b:	mov    %r8,%r9
  40a07e:	sar    %cl,%r12
  40a081:	sar    %cl,%r9
  40a084:	cmp    %r9,%r12
  40a087:	je     40a6e8 <Trace_Ray+0x13f8>
  40a08d:	add    $0x1,%rsi
  40a091:	cmp    %rsi,%rbx
  40a094:	jne    40a175 <Trace_Ray+0xe85>
  40a09a:	jmpq   40a370 <Trace_Ray+0x1080>
  40a09f:	nop
  40a0a0:	lea    0x1(%rsi),%r9
  40a0a4:	mov    %r15,%r12
  40a0a7:	mov    %r8,%rbp
  40a0aa:	lea    0x1(%r9),%ecx
  40a0ae:	mov    %r9,%rsi
  40a0b1:	sar    %cl,%r12
  40a0b4:	sar    %cl,%rbp
  40a0b7:	cmp    %rbp,%r12
  40a0ba:	je     40a500 <Trace_Ray+0x1210>
  40a0c0:	lea    0x1(%r9),%rsi
  40a0c4:	mov    %r15,%rax
  40a0c7:	mov    %r8,%r14
  40a0ca:	lea    0x1(%rsi),%ecx
  40a0cd:	sar    %cl,%rax
  40a0d0:	sar    %cl,%r14
  40a0d3:	cmp    %r14,%rax
  40a0d6:	je     40a538 <Trace_Ray+0x1248>
  40a0dc:	lea    0x2(%r9),%rsi
  40a0e0:	mov    %r15,%r12
  40a0e3:	mov    %r8,%rbp
  40a0e6:	lea    0x1(%rsi),%ecx
  40a0e9:	sar    %cl,%r12
  40a0ec:	sar    %cl,%rbp
  40a0ef:	cmp    %rbp,%r12
  40a0f2:	je     40a570 <Trace_Ray+0x1280>
  40a0f8:	lea    0x3(%r9),%rsi
  40a0fc:	mov    %r15,%rax
  40a0ff:	mov    %r8,%r14
  40a102:	lea    0x1(%rsi),%ecx
  40a105:	sar    %cl,%rax
  40a108:	sar    %cl,%r14
  40a10b:	cmp    %r14,%rax
  40a10e:	je     40a5a8 <Trace_Ray+0x12b8>
  40a114:	lea    0x4(%r9),%rsi
  40a118:	mov    %r15,%r12
  40a11b:	mov    %r8,%rbp
  40a11e:	lea    0x1(%rsi),%ecx
  40a121:	sar    %cl,%r12
  40a124:	sar    %cl,%rbp
  40a127:	cmp    %rbp,%r12
  40a12a:	je     40a5e0 <Trace_Ray+0x12f0>
  40a130:	lea    0x5(%r9),%rsi
  40a134:	mov    %r15,%rax
  40a137:	mov    %r8,%r14
  40a13a:	lea    0x1(%rsi),%ecx
  40a13d:	sar    %cl,%rax
  40a140:	sar    %cl,%r14
  40a143:	cmp    %r14,%rax
  40a146:	je     40a618 <Trace_Ray+0x1328>
  40a14c:	lea    0x6(%r9),%rsi
  40a150:	mov    %r15,%r12
  40a153:	mov    %r8,%rbp
  40a156:	lea    0x1(%rsi),%ecx
  40a159:	sar    %cl,%r12
  40a15c:	sar    %cl,%rbp
  40a15f:	cmp    %rbp,%r12
  40a162:	je     40a650 <Trace_Ray+0x1360>
  40a168:	lea    0x7(%r9),%rsi
  40a16c:	cmp    %rsi,%rbx
  40a16f:	je     40a370 <Trace_Ray+0x1080>
  40a175:	lea    0x1(%rsi),%ecx
  40a178:	mov    %r15,%rax
  40a17b:	mov    %r8,%r9
  40a17e:	sar    %cl,%rax
  40a181:	sar    %cl,%r9
  40a184:	cmp    %r9,%rax
  40a187:	jne    40a0a0 <Trace_Ray+0xdb0>
  40a18d:	mov    %rdx,%rbp
  40a190:	mov    %r11,%r12
  40a193:	sar    %cl,%rbp
  40a196:	sar    %cl,%r12
  40a199:	cmp    %r12,%rbp
  40a19c:	jne    40a0a0 <Trace_Ray+0xdb0>
  40a1a2:	mov    -0x60(%rsp),%r14
  40a1a7:	mov    %rdi,%rax
  40a1aa:	sar    %cl,%rax
  40a1ad:	sar    %cl,%r14
  40a1b0:	cmp    %r14,%rax
  40a1b3:	jne    40a0a0 <Trace_Ray+0xdb0>
  40a1b9:	nopl   0x0(%rax)
  40a1c0:	mov    0x6445c0(,%rsi,8),%r11
  40a1c8:	lea    (%rsi,%rsi,2),%r9
  40a1cc:	mov    %rdi,-0x60(%rsp)
  40a1d1:	mov    %r15,%r8
  40a1d4:	movss  -0x64(%rsp),%xmm0
  40a1da:	add    %r9,%r9
  40a1dd:	mov    %r11,-0x50(%rsp)
  40a1e2:	movswq 0x644502(%r9),%r12
  40a1ea:	mov    %rdx,%r11
  40a1ed:	movswq 0x644500(%r9),%rbp
  40a1f5:	jmpq   409890 <Trace_Ray+0x5a0>
  40a1fa:	nopw   0x0(%rax,%rax,1)
  40a200:	pxor   %xmm12,%xmm12
  40a205:	ucomiss -0x40(%rsp),%xmm12
  40a20b:	ja     40a338 <Trace_Ray+0x1048>
  40a211:	movswl 0x23a3f8(%rip),%edx        # 644610 <opc_len>
  40a218:	pxor   %xmm13,%xmm13
  40a21d:	movss  -0x40(%rsp),%xmm14
  40a224:	sub    $0x1,%edx
  40a227:	cvtsi2ss %edx,%xmm13
  40a22c:	ucomiss %xmm13,%xmm14
  40a230:	jbe    40a888 <Trace_Ray+0x1598>
  40a236:	ucomiss %xmm13,%xmm9
  40a23a:	jbe    40a908 <Trace_Ray+0x1618>
  40a240:	add    $0xc0,%rsp
  40a247:	pop    %rbx
  40a248:	pop    %rbp
  40a249:	pop    %r12
  40a24b:	pop    %r13
  40a24d:	pop    %r14
  40a24f:	pop    %r15
  40a251:	retq   
  40a252:	nopw   0x0(%rax,%rax,1)
  40a258:	pxor   %xmm8,%xmm8
  40a25d:	ucomiss -0x48(%rsp),%xmm8
  40a263:	ja     40a8a0 <Trace_Ray+0x15b0>
  40a269:	movswl 0x23a3a2(%rip),%ebx        # 644612 <opc_len+0x2>
  40a270:	pxor   %xmm9,%xmm9
  40a275:	movss  -0x48(%rsp),%xmm3
  40a27b:	sub    $0x1,%ebx
  40a27e:	cvtsi2ss %ebx,%xmm9
  40a283:	ucomiss %xmm9,%xmm3
  40a287:	jbe    409539 <Trace_Ray+0x249>
  40a28d:	ucomiss %xmm9,%xmm10
  40a291:	ja     40a240 <Trace_Ray+0xf50>
  40a293:	jmpq   409539 <Trace_Ray+0x249>
  40a298:	nopl   0x0(%rax,%rax,1)
  40a2a0:	xorps  0xeb58(%rip),%xmm9        # 418e00 <__dso_handle+0x38>
  40a2a8:	pxor   %xmm3,%xmm3
  40a2ac:	cvtss2sd %xmm9,%xmm3
  40a2b1:	ucomisd %xmm3,%xmm15
  40a2b6:	ja     40a258 <Trace_Ray+0xf68>
  40a2b8:	jmpq   4094cc <Trace_Ray+0x1dc>
  40a2bd:	nopl   (%rax)
  40a2c0:	pxor   %xmm13,%xmm13
  40a2c5:	movswl 0x23a348(%rip),%esi        # 644614 <opc_len+0x4>
  40a2cc:	movss  -0x3c(%rsp),%xmm11
  40a2d3:	pxor   %xmm5,%xmm5
  40a2d7:	pxor   %xmm7,%xmm7
  40a2db:	cvtss2sd %xmm11,%xmm13
  40a2e0:	pxor   %xmm14,%xmm14
  40a2e5:	sub    $0x1,%esi
  40a2e8:	subsd  %xmm13,%xmm5
  40a2ed:	pxor   %xmm8,%xmm8
  40a2f2:	cvtsi2ss %esi,%xmm7
  40a2f6:	cvtss2sd %xmm10,%xmm14
  40a2fb:	divsd  %xmm14,%xmm5
  40a300:	subss  %xmm11,%xmm7
  40a305:	divss  %xmm10,%xmm7
  40a30a:	cvtsd2ss %xmm5,%xmm8
  40a30f:	movaps %xmm8,%xmm9
  40a313:	maxss  %xmm7,%xmm8
  40a318:	minss  %xmm7,%xmm9
  40a31d:	minss  %xmm0,%xmm8
  40a322:	maxss  %xmm4,%xmm9
  40a327:	movaps %xmm8,%xmm0
  40a32b:	movaps %xmm9,%xmm4
  40a32f:	jmpq   4095b0 <Trace_Ray+0x2c0>
  40a334:	nopl   0x0(%rax)
  40a338:	ucomiss %xmm9,%xmm12
  40a33c:	jbe    40a211 <Trace_Ray+0xf21>
  40a342:	jmpq   40a240 <Trace_Ray+0xf50>
  40a347:	nopw   0x0(%rax,%rax,1)
  40a350:	ucomiss %xmm11,%xmm3
  40a354:	jbe    40957d <Trace_Ray+0x28d>
  40a35a:	jmpq   40a240 <Trace_Ray+0xf50>
  40a35f:	nop
  40a360:	subsd  %xmm15,%xmm5
  40a365:	cvttsd2si %xmm5,%r8
  40a36a:	jmpq   40965b <Trace_Ray+0x36b>
  40a36f:	nop
  40a370:	mov    0x48(%rsp),%r8
  40a375:	mov    %rdi,-0x60(%rsp)
  40a37a:	mov    %rdx,%r11
  40a37d:	movss  -0x64(%rsp),%xmm0
  40a383:	mov    %r8,-0x50(%rsp)
  40a388:	mov    %r15,%r8
  40a38b:	mov    0x50(%rsp),%r15
  40a390:	movswq 0x2(%r15),%r12
  40a395:	movswq (%r15),%rbp
  40a399:	jmpq   409890 <Trace_Ray+0x5a0>
  40a39e:	xchg   %ax,%ax
  40a3a0:	movsd  0xf518(%rip),%xmm3        # 4198c0 <__dso_handle+0xaf8>
  40a3a8:	ucomisd -0x20(%rsp),%xmm3
  40a3ae:	jbe    4099e6 <Trace_Ray+0x6f6>
  40a3b4:	movss  -0x6c(%rsp),%xmm4
  40a3ba:	pxor   %xmm10,%xmm10
  40a3bf:	cvttss2si %xmm4,%rdi
  40a3c4:	cvtsi2ss %rdi,%xmm10
  40a3c9:	ucomiss %xmm4,%xmm10
  40a3cd:	jp     40a3da <Trace_Ray+0x10ea>
  40a3cf:	sete   %r14b
  40a3d3:	movzbl %r14b,%ecx
  40a3d7:	sub    %rcx,%rdi
  40a3da:	mov    %r9d,%ecx
  40a3dd:	lea    (%rsi,%rsi,2),%r9
  40a3e1:	sar    %cl,%rdi
  40a3e4:	pxor   %xmm6,%xmm6
  40a3e8:	movswq 0x644544(%r9,%r9,1),%rax
  40a3f1:	imul   %rax,%rdi
  40a3f5:	cvtsi2ss %rdi,%xmm6
  40a3fa:	subss  -0x6c(%rsp),%xmm6
  40a400:	mulss  0x78(%rsp),%xmm6
  40a406:	minss  %xmm6,%xmm11
  40a40b:	jmpq   4099e6 <Trace_Ray+0x6f6>
  40a410:	movsd  0xf4a8(%rip),%xmm2        # 4198c0 <__dso_handle+0xaf8>
  40a418:	ucomisd -0x28(%rsp),%xmm2
  40a41e:	jbe    409997 <Trace_Ray+0x6a7>
  40a424:	movss  -0x68(%rsp),%xmm12
  40a42b:	pxor   %xmm13,%xmm13
  40a430:	cvttss2si %xmm12,%r14
  40a435:	cvtsi2ss %r14,%xmm13
  40a43a:	ucomiss %xmm12,%xmm13
  40a43e:	jp     40a449 <Trace_Ray+0x1159>
  40a440:	sete   %al
  40a443:	movzbl %al,%ecx
  40a446:	sub    %rcx,%r14
  40a449:	lea    (%rsi,%rsi,2),%rdx
  40a44d:	mov    %r9d,%ecx
  40a450:	sar    %cl,%r14
  40a453:	pxor   %xmm5,%xmm5
  40a457:	movswq 0x644542(%rdx,%rdx,1),%rdi
  40a460:	imul   %rdi,%r14
  40a464:	cvtsi2ss %r14,%xmm5
  40a469:	subss  -0x68(%rsp),%xmm5
  40a46f:	mulss  0x44(%rsp),%xmm5
  40a475:	minss  %xmm5,%xmm11
  40a47a:	jmpq   409997 <Trace_Ray+0x6a7>
  40a47f:	nop
  40a480:	movsd  0xf438(%rip),%xmm3        # 4198c0 <__dso_handle+0xaf8>
  40a488:	ucomisd -0x30(%rsp),%xmm3
  40a48e:	jbe    40993b <Trace_Ray+0x64b>
  40a494:	movss  -0x54(%rsp),%xmm4
  40a49a:	pxor   %xmm10,%xmm10
  40a49f:	cvttss2si %xmm4,%rax
  40a4a4:	cvtsi2ss %rax,%xmm10
  40a4a9:	ucomiss %xmm4,%xmm10
  40a4ad:	jp     40a4b8 <Trace_Ray+0x11c8>
  40a4af:	sete   %dl
  40a4b2:	movzbl %dl,%ecx
  40a4b5:	sub    %rcx,%rax
  40a4b8:	lea    (%rsi,%rsi,2),%rdi
  40a4bc:	mov    %r9d,%ecx
  40a4bf:	sar    %cl,%rax
  40a4c2:	pxor   %xmm11,%xmm11
  40a4c7:	movswq 0x644540(%rdi,%rdi,1),%r14
  40a4d0:	imul   %r14,%rax
  40a4d4:	cvtsi2ss %rax,%xmm11
  40a4d9:	subss  -0x54(%rsp),%xmm11
  40a4e0:	mulss  0x40(%rsp),%xmm11
  40a4e7:	ucomiss 0xf3c1(%rip),%xmm11        # 4198b0 <__dso_handle+0xae8>
  40a4ef:	jbe    409944 <Trace_Ray+0x654>
  40a4f5:	jmpq   40993b <Trace_Ray+0x64b>
  40a4fa:	nopw   0x0(%rax,%rax,1)
  40a500:	mov    %rdx,%rax
  40a503:	mov    %r11,%r14
  40a506:	sar    %cl,%rax
  40a509:	sar    %cl,%r14
  40a50c:	cmp    %r14,%rax
  40a50f:	jne    40a0c0 <Trace_Ray+0xdd0>
  40a515:	mov    -0x60(%rsp),%rbp
  40a51a:	mov    %rdi,%r12
  40a51d:	sar    %cl,%r12
  40a520:	sar    %cl,%rbp
  40a523:	cmp    %rbp,%r12
  40a526:	jne    40a0c0 <Trace_Ray+0xdd0>
  40a52c:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a531:	nopl   0x0(%rax)
  40a538:	mov    %rdx,%r12
  40a53b:	mov    %r11,%rbp
  40a53e:	sar    %cl,%r12
  40a541:	sar    %cl,%rbp
  40a544:	cmp    %rbp,%r12
  40a547:	jne    40a0dc <Trace_Ray+0xdec>
  40a54d:	mov    -0x60(%rsp),%r14
  40a552:	mov    %rdi,%rax
  40a555:	sar    %cl,%rax
  40a558:	sar    %cl,%r14
  40a55b:	cmp    %r14,%rax
  40a55e:	jne    40a0dc <Trace_Ray+0xdec>
  40a564:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a569:	nopl   0x0(%rax)
  40a570:	mov    %rdx,%rax
  40a573:	mov    %r11,%r14
  40a576:	sar    %cl,%rax
  40a579:	sar    %cl,%r14
  40a57c:	cmp    %r14,%rax
  40a57f:	jne    40a0f8 <Trace_Ray+0xe08>
  40a585:	mov    -0x60(%rsp),%rbp
  40a58a:	mov    %rdi,%r12
  40a58d:	sar    %cl,%r12
  40a590:	sar    %cl,%rbp
  40a593:	cmp    %rbp,%r12
  40a596:	jne    40a0f8 <Trace_Ray+0xe08>
  40a59c:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a5a1:	nopl   0x0(%rax)
  40a5a8:	mov    %rdx,%r12
  40a5ab:	mov    %r11,%rbp
  40a5ae:	sar    %cl,%r12
  40a5b1:	sar    %cl,%rbp
  40a5b4:	cmp    %rbp,%r12
  40a5b7:	jne    40a114 <Trace_Ray+0xe24>
  40a5bd:	mov    -0x60(%rsp),%r14
  40a5c2:	mov    %rdi,%rax
  40a5c5:	sar    %cl,%rax
  40a5c8:	sar    %cl,%r14
  40a5cb:	cmp    %r14,%rax
  40a5ce:	jne    40a114 <Trace_Ray+0xe24>
  40a5d4:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a5d9:	nopl   0x0(%rax)
  40a5e0:	mov    %rdx,%rax
  40a5e3:	mov    %r11,%r14
  40a5e6:	sar    %cl,%rax
  40a5e9:	sar    %cl,%r14
  40a5ec:	cmp    %r14,%rax
  40a5ef:	jne    40a130 <Trace_Ray+0xe40>
  40a5f5:	mov    -0x60(%rsp),%rbp
  40a5fa:	mov    %rdi,%r12
  40a5fd:	sar    %cl,%r12
  40a600:	sar    %cl,%rbp
  40a603:	cmp    %rbp,%r12
  40a606:	jne    40a130 <Trace_Ray+0xe40>
  40a60c:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a611:	nopl   0x0(%rax)
  40a618:	mov    %rdx,%r12
  40a61b:	mov    %r11,%rbp
  40a61e:	sar    %cl,%r12
  40a621:	sar    %cl,%rbp
  40a624:	cmp    %rbp,%r12
  40a627:	jne    40a14c <Trace_Ray+0xe5c>
  40a62d:	mov    -0x60(%rsp),%r14
  40a632:	mov    %rdi,%rax
  40a635:	sar    %cl,%rax
  40a638:	sar    %cl,%r14
  40a63b:	cmp    %r14,%rax
  40a63e:	jne    40a14c <Trace_Ray+0xe5c>
  40a644:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a649:	nopl   0x0(%rax)
  40a650:	mov    %rdx,%rax
  40a653:	mov    %r11,%r14
  40a656:	sar    %cl,%rax
  40a659:	sar    %cl,%r14
  40a65c:	cmp    %r14,%rax
  40a65f:	jne    40a168 <Trace_Ray+0xe78>
  40a665:	mov    -0x60(%rsp),%rbp
  40a66a:	mov    %rdi,%r12
  40a66d:	sar    %cl,%r12
  40a670:	sar    %cl,%rbp
  40a673:	cmp    %rbp,%r12
  40a676:	jne    40a168 <Trace_Ray+0xe78>
  40a67c:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a681:	nopl   0x0(%rax)
  40a688:	subsd  %xmm15,%xmm3
  40a68d:	cmp    %rbx,%rsi
  40a690:	cvttsd2si %xmm3,%rdi
  40a695:	jl     409f8d <Trace_Ray+0xc9d>
  40a69b:	mov    %rdi,-0x60(%rsp)
  40a6a0:	mov    %rdx,%r11
  40a6a3:	mov    %r15,%r8
  40a6a6:	movss  -0x64(%rsp),%xmm0
  40a6ac:	jmpq   409890 <Trace_Ray+0x5a0>
  40a6b1:	nopl   0x0(%rax)
  40a6b8:	subsd  %xmm15,%xmm5
  40a6bd:	movaps %xmm1,%xmm7
  40a6c0:	cvttsd2si %xmm5,%rdx
  40a6c5:	jmpq   409f61 <Trace_Ray+0xc71>
  40a6ca:	nopw   0x0(%rax,%rax,1)
  40a6d0:	subsd  %xmm15,%xmm6
  40a6d5:	movaps %xmm10,%xmm1
  40a6d9:	cvttsd2si %xmm6,%r15
  40a6de:	jmpq   409f3b <Trace_Ray+0xc4b>
  40a6e3:	nopl   0x0(%rax,%rax,1)
  40a6e8:	mov    %rdx,%rax
  40a6eb:	mov    %r11,%rbp
  40a6ee:	sar    %cl,%rax
  40a6f1:	sar    %cl,%rbp
  40a6f4:	cmp    %rbp,%rax
  40a6f7:	jne    40a08d <Trace_Ray+0xd9d>
  40a6fd:	mov    -0x60(%rsp),%r14
  40a702:	mov    %rdi,%r12
  40a705:	sar    %cl,%r12
  40a708:	sar    %cl,%r14
  40a70b:	cmp    %r14,%r12
  40a70e:	jne    40a08d <Trace_Ray+0xd9d>
  40a714:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a719:	nopl   0x0(%rax)
  40a720:	sub    $0x1,%rsi
  40a724:	mov    -0x60(%rsp),%rdi
  40a729:	mov    0x6445c0(,%rsi,8),%rbp
  40a731:	lea    (%rsi,%rsi,2),%r14
  40a735:	add    %r14,%r14
  40a738:	mov    %rbp,-0x50(%rsp)
  40a73d:	movswq 0x644502(%r14),%r12
  40a745:	movswq 0x644500(%r14),%rbp
  40a74d:	jmpq   409890 <Trace_Ray+0x5a0>
  40a752:	nopw   0x0(%rax,%rax,1)
  40a758:	mov    %rdx,%r9
  40a75b:	mov    %r11,%rbp
  40a75e:	sar    %cl,%r9
  40a761:	sar    %cl,%rbp
  40a764:	cmp    %rbp,%r9
  40a767:	jne    40a071 <Trace_Ray+0xd81>
  40a76d:	mov    -0x60(%rsp),%r14
  40a772:	mov    %rdi,%rax
  40a775:	sar    %cl,%rax
  40a778:	sar    %cl,%r14
  40a77b:	cmp    %r14,%rax
  40a77e:	jne    40a071 <Trace_Ray+0xd81>
  40a784:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a789:	nopl   0x0(%rax)
  40a790:	mov    %rdx,%r12
  40a793:	mov    %r11,%rbp
  40a796:	sar    %cl,%r12
  40a799:	sar    %cl,%rbp
  40a79c:	cmp    %rbp,%r12
  40a79f:	jne    40a055 <Trace_Ray+0xd65>
  40a7a5:	mov    -0x60(%rsp),%r14
  40a7aa:	mov    %rdi,%r9
  40a7ad:	sar    %cl,%r9
  40a7b0:	sar    %cl,%r14
  40a7b3:	cmp    %r14,%r9
  40a7b6:	jne    40a055 <Trace_Ray+0xd65>
  40a7bc:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a7c1:	nopl   0x0(%rax)
  40a7c8:	mov    %rdx,%rax
  40a7cb:	mov    %r11,%rbp
  40a7ce:	sar    %cl,%rax
  40a7d1:	sar    %cl,%rbp
  40a7d4:	cmp    %rbp,%rax
  40a7d7:	jne    40a039 <Trace_Ray+0xd49>
  40a7dd:	mov    -0x60(%rsp),%r14
  40a7e2:	mov    %rdi,%r12
  40a7e5:	sar    %cl,%r12
  40a7e8:	sar    %cl,%r14
  40a7eb:	cmp    %r14,%r12
  40a7ee:	jne    40a039 <Trace_Ray+0xd49>
  40a7f4:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a7f9:	nopl   0x0(%rax)
  40a800:	movaps %xmm11,%xmm9
  40a804:	mov    0x60(%rsp),%rbx
  40a809:	pxor   %xmm12,%xmm12
  40a80e:	movss  -0x44(%rsp),%xmm14
  40a815:	subss  %xmm9,%xmm14
  40a81a:	pxor   %xmm13,%xmm13
  40a81f:	movzbl (%rbx),%edx
  40a822:	cvtsi2ss %edx,%xmm12
  40a827:	mulss  %xmm12,%xmm14
  40a82c:	addss  -0x58(%rsp),%xmm14
  40a833:	cvtss2sd %xmm14,%xmm13
  40a838:	addsd  0xee17(%rip),%xmm13        # 419658 <__dso_handle+0x890>
  40a841:	cvttsd2si %xmm13,%rax
  40a846:	mov    %al,(%rbx)
  40a848:	jmpq   40a240 <Trace_Ray+0xf50>
  40a84d:	nopl   (%rax)
  40a850:	mov    %rdx,%r9
  40a853:	mov    %r11,%rbp
  40a856:	sar    %cl,%r9
  40a859:	sar    %cl,%rbp
  40a85c:	cmp    %rbp,%r9
  40a85f:	jne    40a01d <Trace_Ray+0xd2d>
  40a865:	mov    -0x60(%rsp),%r14
  40a86a:	mov    %rdi,%rax
  40a86d:	sar    %cl,%rax
  40a870:	sar    %cl,%r14
  40a873:	cmp    %r14,%rax
  40a876:	jne    40a01d <Trace_Ray+0xd2d>
  40a87c:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a881:	nopl   0x0(%rax)
  40a888:	movss  0xe56c(%rip),%xmm0        # 418dfc <__dso_handle+0x34>
  40a890:	movss  %xmm0,-0x44(%rsp)
  40a896:	pxor   %xmm4,%xmm4
  40a89a:	jmpq   40949b <Trace_Ray+0x1ab>
  40a89f:	nop
  40a8a0:	ucomiss %xmm10,%xmm8
  40a8a4:	jbe    40a269 <Trace_Ray+0xf79>
  40a8aa:	jmpq   40a240 <Trace_Ray+0xf50>
  40a8af:	nop
  40a8b0:	movss  0x23a938(%rip),%xmm4        # 6451f0 <opacity_epsilon>
  40a8b8:	ucomiss %xmm9,%xmm4
  40a8bc:	jae    40a240 <Trace_Ray+0xf50>
  40a8c2:	jmpq   40a804 <Trace_Ray+0x1514>
  40a8c7:	nopw   0x0(%rax,%rax,1)
  40a8d0:	mov    %rdx,%r12
  40a8d3:	mov    %r11,%rbp
  40a8d6:	sar    %cl,%r12
  40a8d9:	sar    %cl,%rbp
  40a8dc:	cmp    %rbp,%r12
  40a8df:	jne    40a001 <Trace_Ray+0xd11>
  40a8e5:	mov    -0x60(%rsp),%r14
  40a8ea:	mov    %rdi,%r9
  40a8ed:	sar    %cl,%r9
  40a8f0:	sar    %cl,%r14
  40a8f3:	cmp    %r14,%r9
  40a8f6:	jne    40a001 <Trace_Ray+0xd11>
  40a8fc:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a901:	nopl   0x0(%rax)
  40a908:	movss  0xe4ec(%rip),%xmm0        # 418dfc <__dso_handle+0x34>
  40a910:	movss  %xmm0,-0x44(%rsp)
  40a916:	pxor   %xmm4,%xmm4
  40a91a:	jmpq   40949b <Trace_Ray+0x1ab>
  40a91f:	nop
  40a920:	subsd  %xmm15,%xmm8
  40a925:	movaps %xmm14,%xmm3
  40a929:	cvttsd2si %xmm8,%r11
  40a92e:	jmpq   409685 <Trace_Ray+0x395>
  40a933:	nopl   0x0(%rax,%rax,1)
  40a938:	subsd  %xmm15,%xmm9
  40a93d:	cvttsd2si %xmm9,%r9
  40a942:	mov    %r9,-0x60(%rsp)
  40a947:	jmpq   4096af <Trace_Ray+0x3bf>
  40a94c:	nopl   0x0(%rax)
  40a950:	mov    %rdx,%rax
  40a953:	mov    %r11,%rbp
  40a956:	sar    %cl,%rax
  40a959:	sar    %cl,%rbp
  40a95c:	cmp    %rbp,%rax
  40a95f:	jne    409fe5 <Trace_Ray+0xcf5>
  40a965:	mov    -0x60(%rsp),%r9
  40a96a:	mov    %rdi,%r12
  40a96d:	sar    %cl,%r12
  40a970:	sar    %cl,%r9
  40a973:	cmp    %r9,%r12
  40a976:	jne    409fe5 <Trace_Ray+0xcf5>
  40a97c:	jmpq   40a1c0 <Trace_Ray+0xed0>
  40a981:	nopl   0x0(%rax,%rax,1)
  40a986:	nopw   %cs:0x0(%rax,%rax,1)

000000000040a990 <Pre_Shade>:
  40a990:	push   %r15
  40a992:	pxor   %xmm1,%xmm1
  40a996:	push   %r14
  40a998:	push   %r13
  40a99a:	push   %r12
  40a99c:	push   %rbp
  40a99d:	push   %rbx
  40a99e:	pxor   %xmm2,%xmm2
  40a9a2:	sub    $0x38,%rsp
  40a9a6:	cvtsi2ssq 0x239aa1(%rip),%xmm1        # 644450 <num_nodes>
  40a9af:	movss  0xe445(%rip),%xmm0        # 418dfc <__dso_handle+0x34>
  40a9b7:	divss  %xmm1,%xmm0
  40a9bb:	mulss  0xeef1(%rip),%xmm0        # 4198b4 <__dso_handle+0xaec>
  40a9c3:	cvttss2si %xmm0,%rax
  40a9c8:	cvtsi2ss %rax,%xmm2
  40a9cd:	ucomiss %xmm2,%xmm0
  40a9d0:	jp     40a9d4 <Pre_Shade+0x44>
  40a9d2:	je     40a9d8 <Pre_Shade+0x48>
  40a9d4:	add    $0x1,%rax
  40a9d8:	imul   %rax,%rdi
  40a9dc:	mov    $0x20,%r13d
  40a9e2:	lea    -0x1f(%rdi),%rbp
  40a9e6:	add    %rbp,%rax
  40a9e9:	cmp    $0x20,%rax
  40a9ed:	cmovl  %rax,%r13
  40a9f1:	cmp    %rbp,%r13
  40a9f4:	jle    40ad19 <Pre_Shade+0x389>
  40a9fa:	mov    %rbp,%rdx
  40a9fd:	pxor   %xmm3,%xmm3
  40aa01:	shl    $0x6,%rdx
  40aa05:	mov    $0xffffffff,%ebx
  40aa0a:	sub    %rbp,%rdx
  40aa0d:	lea    0xf42(%rdx,%rdx,1),%r12
  40aa15:	nopl   (%rax)
  40aa18:	pxor   %xmm4,%xmm4
  40aa1c:	mov    %r12,%r15
  40aa1f:	mov    $0xffffffffffffffe1,%r14
  40aa26:	pxor   %xmm5,%xmm5
  40aa2a:	pxor   %xmm6,%xmm6
  40aa2e:	cvtsi2ss %rbp,%xmm4
  40aa33:	pxor   %xmm8,%xmm8
  40aa38:	movsd  0xee8f(%rip),%xmm9        # 4198d0 <__dso_handle+0xb08>
  40aa41:	cvtss2sd %xmm4,%xmm5
  40aa45:	mulsd  0xee8b(%rip),%xmm5        # 4198d8 <__dso_handle+0xb10>
  40aa4d:	cvtsd2ss %xmm5,%xmm6
  40aa51:	movss  %xmm6,0x2c(%rsp)
  40aa57:	mulss  %xmm6,%xmm6
  40aa5b:	cvtss2sd %xmm6,%xmm8
  40aa60:	subsd  %xmm8,%xmm9
  40aa65:	movsd  %xmm9,0x8(%rsp)
  40aa6c:	jmpq   40ac23 <Pre_Shade+0x293>
  40aa71:	nopl   0x0(%rax)
  40aa78:	pxor   %xmm0,%xmm0
  40aa7c:	cvtss2sd %xmm9,%xmm0
  40aa81:	movss  %xmm1,0x10(%rsp)
  40aa87:	pxor   %xmm1,%xmm1
  40aa8b:	movss  %xmm3,0x24(%rsp)
  40aa91:	movss  %xmm8,0x28(%rsp)
  40aa98:	cvtss2sd 0x239fc0(%rip),%xmm1        # 644a60 <specular_exponent>
  40aaa0:	movss  %xmm7,0x20(%rsp)
  40aaa6:	movss  %xmm5,0x1c(%rsp)
  40aaac:	movss  %xmm6,0x18(%rsp)
  40aab2:	movss  %xmm4,0x14(%rsp)
  40aab8:	callq  4011d0 <pow@plt>
  40aabd:	pxor   %xmm10,%xmm10
  40aac2:	mov    %ebx,%r8d
  40aac5:	movss  0x28(%rsp),%xmm3
  40aacb:	mulss  0x23a6a5(%rip),%xmm3        # 645178 <diffuse_color>
  40aad3:	movss  0xeb84(%rip),%xmm11        # 419660 <__dso_handle+0x898>
  40aadc:	cvtsd2ss %xmm0,%xmm10
  40aae1:	movss  0x10(%rsp),%xmm12
  40aae8:	movss  0x14(%rsp),%xmm13
  40aaef:	addss  0x23a6c1(%rip),%xmm3        # 6451b8 <ambient_color>
  40aaf7:	movss  0x18(%rsp),%xmm14
  40aafe:	movss  0x1c(%rsp),%xmm15
  40ab05:	movss  0x20(%rsp),%xmm1
  40ab0b:	mulss  0x23a6e0(%rip),%xmm10        # 6451f4 <specular_color>
  40ab14:	addss  %xmm3,%xmm10
  40ab19:	movss  0x24(%rsp),%xmm3
  40ab1f:	ucomiss %xmm10,%xmm11
  40ab23:	jbe    40ab49 <Pre_Shade+0x1b9>
  40ab25:	pxor   %xmm0,%xmm0
  40ab29:	pxor   %xmm5,%xmm5
  40ab2d:	cvtss2sd %xmm10,%xmm0
  40ab32:	addsd  0xeb1e(%rip),%xmm0        # 419658 <__dso_handle+0x890>
  40ab3a:	cvttsd2si %xmm0,%rcx
  40ab3f:	cvtsi2ss %rcx,%xmm5
  40ab44:	cvttss2si %xmm5,%r8
  40ab49:	ucomiss %xmm3,%xmm12
  40ab4d:	mov    0x23777c(%rip),%rsi        # 6422d0 <shd_address>
  40ab54:	mov    %r8b,0x1(%rsi,%r15,1)
  40ab59:	jbe    40ac06 <Pre_Shade+0x276>
  40ab5f:	subss  %xmm1,%xmm15
  40ab64:	pxor   %xmm0,%xmm0
  40ab68:	subss  %xmm14,%xmm13
  40ab6d:	ucomiss %xmm3,%xmm15
  40ab71:	maxss  %xmm3,%xmm13
  40ab76:	jbe    40ab81 <Pre_Shade+0x1f1>
  40ab78:	pxor   %xmm0,%xmm0
  40ab7c:	cvtss2sd %xmm15,%xmm0
  40ab81:	pxor   %xmm1,%xmm1
  40ab85:	movss  %xmm3,0x10(%rsp)
  40ab8b:	movss  %xmm13,0x14(%rsp)
  40ab92:	cvtss2sd 0x239ec6(%rip),%xmm1        # 644a60 <specular_exponent>
  40ab9a:	callq  4011d0 <pow@plt>
  40ab9f:	pxor   %xmm2,%xmm2
  40aba3:	mov    %ebx,%r8d
  40aba6:	movss  0x14(%rsp),%xmm4
  40abac:	mulss  0x23a5c4(%rip),%xmm4        # 645178 <diffuse_color>
  40abb4:	movss  0xeaa4(%rip),%xmm6        # 419660 <__dso_handle+0x898>
  40abbc:	cvtsd2ss %xmm0,%xmm2
  40abc0:	movss  0x10(%rsp),%xmm3
  40abc6:	addss  0x23a5ea(%rip),%xmm4        # 6451b8 <ambient_color>
  40abce:	mulss  0x23a61e(%rip),%xmm2        # 6451f4 <specular_color>
  40abd6:	addss  %xmm4,%xmm2
  40abda:	ucomiss %xmm2,%xmm6
  40abdd:	jbe    40ac06 <Pre_Shade+0x276>
  40abdf:	pxor   %xmm8,%xmm8
  40abe4:	pxor   %xmm9,%xmm9
  40abe9:	cvtss2sd %xmm2,%xmm8
  40abee:	addsd  0xea61(%rip),%xmm8        # 419658 <__dso_handle+0x890>
  40abf7:	cvttsd2si %xmm8,%rdi
  40abfc:	cvtsi2ss %rdi,%xmm9
  40ac01:	cvttss2si %xmm9,%r8
  40ac06:	mov    0x2376c3(%rip),%r9        # 6422d0 <shd_address>
  40ac0d:	mov    %r8b,(%r9,%r15,1)
  40ac11:	add    $0x1,%r14
  40ac15:	add    $0x2,%r15
  40ac19:	cmp    $0x20,%r14
  40ac1d:	je     40ad08 <Pre_Shade+0x378>
  40ac23:	pxor   %xmm10,%xmm10
  40ac28:	pxor   %xmm11,%xmm11
  40ac2d:	pxor   %xmm15,%xmm15
  40ac32:	cvtsi2ss %r14,%xmm10
  40ac37:	pxor   %xmm13,%xmm13
  40ac3c:	movsd  0x8(%rsp),%xmm0
  40ac42:	cvtss2sd %xmm10,%xmm11
  40ac47:	mulsd  0xec88(%rip),%xmm11        # 4198d8 <__dso_handle+0xb10>
  40ac50:	cvtsd2ss %xmm11,%xmm15
  40ac55:	movaps %xmm15,%xmm12
  40ac59:	mulss  %xmm15,%xmm12
  40ac5e:	cvtss2sd %xmm12,%xmm13
  40ac63:	subsd  %xmm13,%xmm0
  40ac68:	cvtsd2ss %xmm0,%xmm0
  40ac6c:	ucomiss 0xec45(%rip),%xmm0        # 4198b8 <__dso_handle+0xaf0>
  40ac73:	jbe    40ac11 <Pre_Shade+0x281>
  40ac75:	ucomiss %xmm3,%xmm0
  40ac78:	movaps %xmm3,%xmm1
  40ac7b:	jbe    40ac8a <Pre_Shade+0x2fa>
  40ac7d:	ucomiss %xmm0,%xmm3
  40ac80:	sqrtss %xmm0,%xmm1
  40ac84:	ja     40ad3f <Pre_Shade+0x3af>
  40ac8a:	movss  0x2c(%rsp),%xmm5
  40ac90:	movss  0x23a568(%rip),%xmm4        # 645200 <obslight+0x8>
  40ac98:	movss  0x23a55c(%rip),%xmm2        # 6451fc <obslight+0x4>
  40aca0:	mulss  %xmm5,%xmm4
  40aca4:	mulss  %xmm15,%xmm2
  40aca9:	movss  0x23a557(%rip),%xmm7        # 645208 <obshighlight>
  40acb1:	mulss  0x23a557(%rip),%xmm5        # 645210 <obshighlight+0x8>
  40acb9:	movss  0x23a537(%rip),%xmm6        # 6451f8 <obslight>
  40acc1:	mulss  0x23a542(%rip),%xmm15        # 64520c <obshighlight+0x4>
  40acca:	mulss  %xmm1,%xmm7
  40acce:	addss  %xmm2,%xmm4
  40acd2:	mulss  %xmm1,%xmm6
  40acd6:	addss  %xmm15,%xmm5
  40acdb:	movaps %xmm4,%xmm8
  40acdf:	addss  %xmm6,%xmm8
  40ace4:	movaps %xmm5,%xmm9
  40ace8:	addss  %xmm7,%xmm9
  40aced:	maxss  %xmm3,%xmm8
  40acf2:	ucomiss %xmm3,%xmm9
  40acf6:	ja     40aa78 <Pre_Shade+0xe8>
  40acfc:	pxor   %xmm0,%xmm0
  40ad00:	jmpq   40aa81 <Pre_Shade+0xf1>
  40ad05:	nopl   (%rax)
  40ad08:	add    $0x1,%rbp
  40ad0c:	add    $0x7e,%r12
  40ad10:	cmp    %rbp,%r13
  40ad13:	jne    40aa18 <Pre_Shade+0x88>
  40ad19:	mov    0x2375b0(%rip),%r11        # 6422d0 <shd_address>
  40ad20:	cvttss2si 0x23a48f(%rip),%r10        # 6451b8 <ambient_color>
  40ad29:	mov    %r10b,0x1ec7(%r11)
  40ad30:	add    $0x38,%rsp
  40ad34:	pop    %rbx
  40ad35:	pop    %rbp
  40ad36:	pop    %r12
  40ad38:	pop    %r13
  40ad3a:	pop    %r14
  40ad3c:	pop    %r15
  40ad3e:	retq   
  40ad3f:	movss  %xmm3,0x18(%rsp)
  40ad45:	movss  %xmm1,0x14(%rsp)
  40ad4b:	movss  %xmm15,0x10(%rsp)
  40ad52:	callq  401240 <sqrtf@plt>
  40ad57:	movss  0x10(%rsp),%xmm15
  40ad5e:	movss  0x14(%rsp),%xmm1
  40ad64:	movss  0x18(%rsp),%xmm3
  40ad6a:	jmpq   40ac8a <Pre_Shade+0x2fa>
  40ad6f:	nop

000000000040ad70 <Observer_Transform_Light_Vector>:
  40ad70:	pxor   %xmm0,%xmm0
  40ad74:	sub    $0x18,%rsp
  40ad78:	pxor   %xmm2,%xmm2
  40ad7c:	mov    $0x645200,%edx
  40ad81:	pxor   %xmm1,%xmm1
  40ad85:	mov    $0x6451fc,%esi
  40ad8a:	cvtss2sd 0x23a42e(%rip),%xmm0        # 6451c0 <light>
  40ad92:	mov    $0x6451f8,%edi
  40ad97:	cvtss2sd 0x23a429(%rip),%xmm2        # 6451c8 <light+0x8>
  40ad9f:	cvtss2sd 0x23a41d(%rip),%xmm1        # 6451c4 <light+0x4>
  40ada7:	callq  40c8d0 <Transform_Point>
  40adac:	movss  0x23a444(%rip),%xmm3        # 6451f8 <obslight>
  40adb4:	movss  0x23a440(%rip),%xmm2        # 6451fc <obslight+0x4>
  40adbc:	movaps %xmm3,%xmm1
  40adbf:	movaps %xmm2,%xmm0
  40adc2:	mulss  %xmm3,%xmm1
  40adc6:	movss  0x23a432(%rip),%xmm4        # 645200 <obslight+0x8>
  40adce:	mulss  %xmm2,%xmm0
  40add2:	movaps %xmm4,%xmm5
  40add5:	pxor   %xmm6,%xmm6
  40add9:	mulss  %xmm4,%xmm5
  40addd:	pxor   %xmm7,%xmm7
  40ade1:	addss  %xmm0,%xmm1
  40ade5:	addss  %xmm5,%xmm1
  40ade9:	cvtss2sd %xmm1,%xmm6
  40aded:	ucomisd %xmm6,%xmm7
  40adf1:	sqrtsd %xmm6,%xmm8
  40adf6:	ja     40ae3d <Observer_Transform_Light_Vector+0xcd>
  40adf8:	movsd  0xeacf(%rip),%xmm9        # 4198d0 <__dso_handle+0xb08>
  40ae01:	pxor   %xmm10,%xmm10
  40ae06:	divsd  %xmm8,%xmm9
  40ae0b:	cvtsd2ss %xmm9,%xmm10
  40ae10:	mulss  %xmm10,%xmm3
  40ae15:	mulss  %xmm10,%xmm2
  40ae1a:	mulss  %xmm4,%xmm10
  40ae1f:	movss  %xmm3,0x23a3d1(%rip)        # 6451f8 <obslight>
  40ae27:	movss  %xmm2,0x23a3cd(%rip)        # 6451fc <obslight+0x4>
  40ae2f:	movss  %xmm10,0x23a3c8(%rip)        # 645200 <obslight+0x8>
  40ae38:	add    $0x18,%rsp
  40ae3c:	retq   
  40ae3d:	movapd %xmm6,%xmm0
  40ae41:	movsd  %xmm8,0x8(%rsp)
  40ae48:	callq  401360 <sqrt@plt>
  40ae4d:	movss  0x23a3a3(%rip),%xmm3        # 6451f8 <obslight>
  40ae55:	movss  0x23a39f(%rip),%xmm2        # 6451fc <obslight+0x4>
  40ae5d:	movss  0x23a39b(%rip),%xmm4        # 645200 <obslight+0x8>
  40ae65:	movsd  0x8(%rsp),%xmm8
  40ae6c:	jmp    40adf8 <Observer_Transform_Light_Vector+0x88>
  40ae6e:	xchg   %ax,%ax

000000000040ae70 <Compute_Observer_Transformed_Highlight_Vector>:
  40ae70:	sub    $0x28,%rsp
  40ae74:	pxor   %xmm1,%xmm1
  40ae78:	lea    0x14(%rsp),%rdi
  40ae7d:	pxor   %xmm0,%xmm0
  40ae81:	movsd  0xea57(%rip),%xmm2        # 4198e0 <__dso_handle+0xb18>
  40ae89:	lea    0x1c(%rsp),%rdx
  40ae8e:	lea    0x4(%rdi),%rsi
  40ae92:	callq  40c8d0 <Transform_Point>
  40ae97:	movss  0x14(%rsp),%xmm2
  40ae9d:	movss  0x18(%rsp),%xmm1
  40aea3:	movaps %xmm2,%xmm0
  40aea6:	movaps %xmm1,%xmm3
  40aea9:	mulss  %xmm2,%xmm0
  40aead:	movss  0x1c(%rsp),%xmm6
  40aeb3:	mulss  %xmm1,%xmm3
  40aeb7:	movaps %xmm6,%xmm4
  40aeba:	pxor   %xmm5,%xmm5
  40aebe:	mulss  %xmm6,%xmm4
  40aec2:	addss  %xmm3,%xmm0
  40aec6:	addss  %xmm4,%xmm0
  40aeca:	cvtss2sd %xmm0,%xmm0
  40aece:	ucomisd %xmm0,%xmm5
  40aed2:	sqrtsd %xmm0,%xmm7
  40aed6:	ja     40afc2 <Compute_Observer_Transformed_Highlight_Vector+0x152>
  40aedc:	movsd  0xe9eb(%rip),%xmm13        # 4198d0 <__dso_handle+0xb08>
  40aee5:	pxor   %xmm12,%xmm12
  40aeea:	movapd %xmm13,%xmm8
  40aeef:	pxor   %xmm0,%xmm0
  40aef3:	divsd  %xmm7,%xmm8
  40aef8:	cvtsd2ss %xmm8,%xmm12
  40aefd:	mulss  %xmm12,%xmm2
  40af02:	mulss  %xmm12,%xmm1
  40af07:	mulss  %xmm6,%xmm12
  40af0c:	movss  %xmm2,0x14(%rsp)
  40af12:	addss  0x23a2de(%rip),%xmm2        # 6451f8 <obslight>
  40af1a:	movss  %xmm1,0x18(%rsp)
  40af20:	addss  0x23a2d4(%rip),%xmm1        # 6451fc <obslight+0x4>
  40af28:	movss  %xmm12,0x1c(%rsp)
  40af2f:	addss  0x23a2c8(%rip),%xmm12        # 645200 <obslight+0x8>
  40af38:	movaps %xmm2,%xmm9
  40af3c:	movss  %xmm2,0x23a2c4(%rip)        # 645208 <obshighlight>
  40af44:	movaps %xmm1,%xmm10
  40af48:	movss  %xmm1,0x23a2bc(%rip)        # 64520c <obshighlight+0x4>
  40af50:	mulss  %xmm2,%xmm9
  40af55:	movaps %xmm12,%xmm11
  40af59:	mulss  %xmm1,%xmm10
  40af5e:	movss  %xmm12,0x23a2a9(%rip)        # 645210 <obshighlight+0x8>
  40af67:	mulss  %xmm12,%xmm11
  40af6c:	addss  %xmm10,%xmm9
  40af71:	addss  %xmm11,%xmm9
  40af76:	cvtss2sd %xmm9,%xmm0
  40af7b:	ucomisd %xmm0,%xmm5
  40af7f:	sqrtsd %xmm0,%xmm14
  40af84:	ja     40aff4 <Compute_Observer_Transformed_Highlight_Vector+0x184>
  40af86:	divsd  %xmm14,%xmm13
  40af8b:	pxor   %xmm15,%xmm15
  40af90:	cvtsd2ss %xmm13,%xmm15
  40af95:	mulss  %xmm15,%xmm2
  40af9a:	mulss  %xmm15,%xmm1
  40af9f:	mulss  %xmm15,%xmm12
  40afa4:	movss  %xmm2,0x23a25c(%rip)        # 645208 <obshighlight>
  40afac:	movss  %xmm1,0x23a258(%rip)        # 64520c <obshighlight+0x4>
  40afb4:	movss  %xmm12,0x23a253(%rip)        # 645210 <obshighlight+0x8>
  40afbd:	add    $0x28,%rsp
  40afc1:	retq   
  40afc2:	movsd  %xmm5,0x8(%rsp)
  40afc8:	movsd  %xmm7,(%rsp)
  40afcd:	callq  401360 <sqrt@plt>
  40afd2:	movss  0x14(%rsp),%xmm2
  40afd8:	movss  0x18(%rsp),%xmm1
  40afde:	movss  0x1c(%rsp),%xmm6
  40afe4:	movsd  0x8(%rsp),%xmm5
  40afea:	movsd  (%rsp),%xmm7
  40afef:	jmpq   40aedc <Compute_Observer_Transformed_Highlight_Vector+0x6c>
  40aff4:	movsd  %xmm13,0x8(%rsp)
  40affb:	movsd  %xmm14,(%rsp)
  40b001:	callq  401360 <sqrt@plt>
  40b006:	movss  0x23a1fa(%rip),%xmm2        # 645208 <obshighlight>
  40b00e:	movss  0x23a1f6(%rip),%xmm1        # 64520c <obshighlight+0x4>
  40b016:	movss  0x23a1f1(%rip),%xmm12        # 645210 <obshighlight+0x8>
  40b01f:	movsd  0x8(%rsp),%xmm13
  40b026:	movsd  (%rsp),%xmm14
  40b02c:	jmpq   40af86 <Compute_Observer_Transformed_Highlight_Vector+0x116>
  40b031:	nopl   0x0(%rax,%rax,1)
  40b036:	nopw   %cs:0x0(%rax,%rax,1)

000000000040b040 <Render>:
  40b040:	push   %rbx
  40b041:	mov    %rdi,%rbx
  40b044:	sub    $0x10,%rsp
  40b048:	test   %rdi,%rdi
  40b04b:	je     40b060 <Render+0x20>
  40b04d:	add    $0x10,%rsp
  40b051:	mov    %rbx,%rdi
  40b054:	pop    %rbx
  40b055:	jmpq   402580 <Ray_Trace>
  40b05a:	nopw   0x0(%rax,%rax,1)
  40b060:	pxor   %xmm0,%xmm0
  40b064:	mov    $0x645200,%edx
  40b069:	pxor   %xmm2,%xmm2
  40b06d:	mov    $0x6451fc,%esi
  40b072:	pxor   %xmm1,%xmm1
  40b076:	mov    $0x6451f8,%edi
  40b07b:	cvtss2sd 0x23a13d(%rip),%xmm0        # 6451c0 <light>
  40b083:	cvtss2sd 0x23a13d(%rip),%xmm2        # 6451c8 <light+0x8>
  40b08b:	cvtss2sd 0x23a131(%rip),%xmm1        # 6451c4 <light+0x4>
  40b093:	callq  40c8d0 <Transform_Point>
  40b098:	movss  0x23a158(%rip),%xmm3        # 6451f8 <obslight>
  40b0a0:	movss  0x23a154(%rip),%xmm2        # 6451fc <obslight+0x4>
  40b0a8:	movaps %xmm3,%xmm1
  40b0ab:	movaps %xmm2,%xmm0
  40b0ae:	mulss  %xmm3,%xmm1
  40b0b2:	movss  0x23a146(%rip),%xmm4        # 645200 <obslight+0x8>
  40b0ba:	mulss  %xmm2,%xmm0
  40b0be:	movaps %xmm4,%xmm5
  40b0c1:	pxor   %xmm6,%xmm6
  40b0c5:	mulss  %xmm4,%xmm5
  40b0c9:	pxor   %xmm7,%xmm7
  40b0cd:	addss  %xmm0,%xmm1
  40b0d1:	addss  %xmm5,%xmm1
  40b0d5:	cvtss2sd %xmm1,%xmm6
  40b0d9:	ucomisd %xmm6,%xmm7
  40b0dd:	sqrtsd %xmm6,%xmm8
  40b0e2:	ja     40b136 <Render+0xf6>
  40b0e4:	movsd  0xe7e3(%rip),%xmm9        # 4198d0 <__dso_handle+0xb08>
  40b0ed:	pxor   %xmm10,%xmm10
  40b0f2:	divsd  %xmm8,%xmm9
  40b0f7:	cvtsd2ss %xmm9,%xmm10
  40b0fc:	mulss  %xmm10,%xmm3
  40b101:	mulss  %xmm10,%xmm2
  40b106:	mulss  %xmm4,%xmm10
  40b10b:	movss  %xmm3,0x23a0e5(%rip)        # 6451f8 <obslight>
  40b113:	movss  %xmm2,0x23a0e1(%rip)        # 6451fc <obslight+0x4>
  40b11b:	movss  %xmm10,0x23a0dc(%rip)        # 645200 <obslight+0x8>
  40b124:	callq  40ae70 <Compute_Observer_Transformed_Highlight_Vector>
  40b129:	add    $0x10,%rsp
  40b12d:	mov    %rbx,%rdi
  40b130:	pop    %rbx
  40b131:	jmpq   402580 <Ray_Trace>
  40b136:	movapd %xmm6,%xmm0
  40b13a:	movsd  %xmm8,0x8(%rsp)
  40b141:	callq  401360 <sqrt@plt>
  40b146:	movss  0x23a0aa(%rip),%xmm3        # 6451f8 <obslight>
  40b14e:	movss  0x23a0a6(%rip),%xmm2        # 6451fc <obslight+0x4>
  40b156:	movss  0x23a0a2(%rip),%xmm4        # 645200 <obslight+0x8>
  40b15e:	movsd  0x8(%rsp),%xmm8
  40b165:	jmpq   40b0e4 <Render+0xa4>
  40b16a:	nopw   0x0(%rax,%rax,1)

000000000040b170 <Compute_Pre_View>:
  40b170:	push   %rbx
  40b171:	pxor   %xmm1,%xmm1
  40b175:	pxor   %xmm2,%xmm2
  40b179:	sub    $0x10,%rsp
  40b17d:	movswl 0x23948c(%rip),%eax        # 644610 <opc_len>
  40b184:	movswl 0x239487(%rip),%edx        # 644612 <opc_len+0x2>
  40b18b:	movswl 0x239482(%rip),%ecx        # 644614 <opc_len+0x4>
  40b192:	pxor   %xmm0,%xmm0
  40b196:	pxor   %xmm5,%xmm5
  40b19a:	sub    $0x1,%eax
  40b19d:	sub    $0x1,%edx
  40b1a0:	cvtsi2ss %eax,%xmm1
  40b1a4:	sub    $0x1,%ecx
  40b1a7:	cvtsi2ss %edx,%xmm2
  40b1ab:	cvtsi2ss %ecx,%xmm0
  40b1af:	movss  %xmm1,0x23e1a9(%rip)        # 649360 <out_diag_len>
  40b1b7:	mulss  %xmm1,%xmm1
  40b1bb:	movss  %xmm2,0x23e1a1(%rip)        # 649364 <out_diag_len+0x4>
  40b1c3:	mulss  %xmm2,%xmm2
  40b1c7:	movss  %xmm0,0x23e199(%rip)        # 649368 <out_diag_len+0x8>
  40b1cf:	mulss  %xmm0,%xmm0
  40b1d3:	addss  %xmm2,%xmm1
  40b1d7:	addss  %xmm1,%xmm0
  40b1db:	ucomiss %xmm0,%xmm5
  40b1de:	sqrtss %xmm0,%xmm3
  40b1e2:	movss  %xmm0,0x23e11e(%rip)        # 649308 <out_diag_length>
  40b1ea:	ja     40b410 <Compute_Pre_View+0x2a0>
  40b1f0:	pxor   %xmm0,%xmm0
  40b1f4:	movss  %xmm3,0x23e10c(%rip)        # 649308 <out_diag_length>
  40b1fc:	cvtss2sd %xmm3,%xmm0
  40b200:	addsd  0xe450(%rip),%xmm0        # 419658 <__dso_handle+0x890>
  40b208:	cvttsd2si %xmm0,%rsi
  40b20d:	lea    0x1(%rsi),%rbx
  40b211:	cmp    $0x1000,%rsi
  40b218:	mov    %rsi,0x23e161(%rip)        # 649380 <image_zlen>
  40b21f:	mov    %rbx,0x23e152(%rip)        # 649378 <frust_len>
  40b226:	jg     40b3f8 <Compute_Pre_View+0x288>
  40b22c:	test   %rsi,%rsi
  40b22f:	js     40b308 <Compute_Pre_View+0x198>
  40b235:	movss  0x239f5a(%rip),%xmm8        # 645198 <depth_hither>
  40b23e:	xor    %ebx,%ebx
  40b240:	jmp    40b26f <Compute_Pre_View+0xff>
  40b242:	nopw   0x0(%rax,%rax,1)
  40b248:	minss  0xdbab(%rip),%xmm13        # 418dfc <__dso_handle+0x34>
  40b251:	mov    0x23e128(%rip),%rsi        # 649380 <image_zlen>
  40b258:	movss  %xmm13,0x645240(,%rbx,4)
  40b262:	add    $0x1,%rbx
  40b266:	cmp    %rbx,%rsi
  40b269:	jl     40b308 <Compute_Pre_View+0x198>
  40b26f:	pxor   %xmm6,%xmm6
  40b273:	pxor   %xmm7,%xmm7
  40b277:	pxor   %xmm4,%xmm4
  40b27b:	cvtsi2ss %rbx,%xmm6
  40b280:	cvtsi2ss %rsi,%xmm7
  40b285:	pxor   %xmm0,%xmm0
  40b289:	cvtss2sd %xmm8,%xmm4
  40b28e:	pxor   %xmm1,%xmm1
  40b292:	movsd  %xmm4,0x8(%rsp)
  40b298:	cvtss2sd 0x2393a0(%rip),%xmm1        # 644640 <depth_exponent>
  40b2a0:	divss  %xmm7,%xmm6
  40b2a4:	cvtss2sd %xmm6,%xmm0
  40b2a8:	callq  4011d0 <pow@plt>
  40b2ad:	movss  0x239ee2(%rip),%xmm8        # 645198 <depth_hither>
  40b2b6:	movaps %xmm8,%xmm9
  40b2ba:	pxor   %xmm10,%xmm10
  40b2bf:	movsd  0x8(%rsp),%xmm11
  40b2c6:	subss  0x239375(%rip),%xmm9        # 644644 <depth_yon>
  40b2cf:	pxor   %xmm13,%xmm13
  40b2d4:	pxor   %xmm12,%xmm12
  40b2d9:	cvtss2sd %xmm9,%xmm10
  40b2de:	mulsd  %xmm10,%xmm0
  40b2e3:	subsd  %xmm0,%xmm11
  40b2e8:	cvtsd2ss %xmm11,%xmm13
  40b2ed:	ucomiss %xmm12,%xmm13
  40b2f1:	ja     40b248 <Compute_Pre_View+0xd8>
  40b2f7:	pxor   %xmm13,%xmm13
  40b2fc:	jmpq   40b251 <Compute_Pre_View+0xe1>
  40b301:	nopl   0x0(%rax)
  40b308:	movswl 0x239301(%rip),%eax        # 644610 <opc_len>
  40b30f:	movswl 0x2392fb(%rip),%r8d        # 644612 <opc_len+0x2>
  40b317:	movswl 0x2392f5(%rip),%r10d        # 644614 <opc_len+0x4>
  40b31f:	pxor   %xmm14,%xmm14
  40b324:	pxor   %xmm5,%xmm5
  40b328:	movswl 0x2391a5(%rip),%ecx        # 6444d4 <norm_len>
  40b32f:	pxor   %xmm0,%xmm0
  40b333:	lea    -0x1(%rax),%edi
  40b336:	lea    -0x1(%r8),%r9d
  40b33a:	lea    0x1(%rax),%r11d
  40b33e:	sub    $0x1,%r10d
  40b342:	movsd  0xdac5(%rip),%xmm15        # 418e10 <__dso_handle+0x48>
  40b34b:	cvtsi2sd %edi,%xmm14
  40b350:	lea    0x1(%rcx),%ebx
  40b353:	cvtsi2sd %r9d,%xmm5
  40b358:	movslq %r11d,%rdx
  40b35b:	cvtsi2sd %r10d,%xmm0
  40b360:	movslq %ebx,%rsi
  40b363:	movsd  0xe55d(%rip),%xmm1        # 4198c8 <__dso_handle+0xb00>
  40b36b:	mov    %rdx,0x23df8e(%rip)        # 649300 <opc_xlen>
  40b372:	pxor   %xmm2,%xmm2
  40b376:	mov    %rsi,0x239ea3(%rip)        # 645220 <norm_xlen>
  40b37d:	pxor   %xmm3,%xmm3
  40b381:	pxor   %xmm4,%xmm4
  40b385:	imul   %r8d,%eax
  40b389:	add    $0x1,%eax
  40b38c:	subsd  %xmm15,%xmm14
  40b391:	cltq   
  40b393:	subsd  %xmm15,%xmm5
  40b398:	mov    %rax,0x239e89(%rip)        # 645228 <opc_xylen>
  40b39f:	movswl 0x239130(%rip),%eax        # 6444d6 <norm_len+0x2>
  40b3a6:	subsd  %xmm15,%xmm0
  40b3ab:	subsd  %xmm1,%xmm14
  40b3b0:	subsd  %xmm1,%xmm5
  40b3b4:	subsd  %xmm1,%xmm0
  40b3b8:	imul   %ecx,%eax
  40b3bb:	cvtsd2ss %xmm14,%xmm2
  40b3c0:	add    $0x1,%eax
  40b3c3:	cvtsd2ss %xmm5,%xmm3
  40b3c7:	cltq   
  40b3c9:	mov    %rax,0x23dfa0(%rip)        # 649370 <norm_xylen>
  40b3d0:	cvtsd2ss %xmm0,%xmm4
  40b3d4:	movss  %xmm2,0x23df34(%rip)        # 649310 <in_max>
  40b3dc:	movss  %xmm3,0x23df30(%rip)        # 649314 <in_max+0x4>
  40b3e4:	movss  %xmm4,0x23df2c(%rip)        # 649318 <in_max+0x8>
  40b3ec:	add    $0x10,%rsp
  40b3f0:	pop    %rbx
  40b3f1:	retq   
  40b3f2:	nopw   0x0(%rax,%rax,1)
  40b3f8:	mov    $0x4198e8,%edi
  40b3fd:	xor    %eax,%eax
  40b3ff:	callq  403650 <Error>
  40b404:	mov    0x23df75(%rip),%rsi        # 649380 <image_zlen>
  40b40b:	jmpq   40b22c <Compute_Pre_View+0xbc>
  40b410:	movss  %xmm3,0x8(%rsp)
  40b416:	callq  401240 <sqrtf@plt>
  40b41b:	movss  0x8(%rsp),%xmm3
  40b421:	jmpq   40b1f0 <Compute_Pre_View+0x80>
  40b426:	nopw   %cs:0x0(%rax,%rax,1)

000000000040b430 <Compute_Input_Dimensions>:
  40b430:	mov    0x23df41(%rip),%rax        # 649378 <frust_len>
  40b437:	pxor   %xmm0,%xmm0
  40b43b:	movss  0x23df60(%rip),%xmm12        # 6493a4 <transformation_matrix+0x4>
  40b444:	movq   $0x0,-0x68(%rsp)
  40b44d:	movaps %xmm12,%xmm11
  40b451:	movl   $0x0,-0x60(%rsp)
  40b459:	sub    $0x1,%rax
  40b45d:	movss  0x23df3b(%rip),%xmm6        # 6493a0 <transformation_matrix>
  40b465:	cvtsi2ss %rax,%xmm0
  40b46a:	movq   $0x0,-0x58(%rsp)
  40b473:	movl   $0x0,-0x50(%rsp)
  40b47b:	movss  0x23df24(%rip),%xmm9        # 6493a8 <transformation_matrix+0x8>
  40b484:	movl   $0x0,-0x48(%rsp)
  40b48c:	unpcklps %xmm9,%xmm11
  40b490:	movss  0x23df1b(%rip),%xmm10        # 6493b4 <transformation_matrix+0x14>
  40b499:	unpcklps %xmm6,%xmm9
  40b49d:	movq   $0x0,-0x3c(%rsp)
  40b4a6:	unpcklps %xmm12,%xmm6
  40b4aa:	movl   $0x0,-0x34(%rsp)
  40b4b2:	movaps %xmm10,%xmm12
  40b4b6:	movl   $0x0,-0x28(%rsp)
  40b4be:	movaps %xmm9,%xmm14
  40b4c2:	movl   $0x0,-0x20(%rsp)
  40b4ca:	movss  0x23def1(%rip),%xmm8        # 6493c4 <transformation_matrix+0x24>
  40b4d3:	movss  0x23def9(%rip),%xmm2        # 6493d4 <transformation_matrix+0x34>
  40b4db:	movlhps %xmm11,%xmm14
  40b4df:	movss  0x23dec9(%rip),%xmm7        # 6493b0 <transformation_matrix+0x10>
  40b4e7:	movss  0x23dec9(%rip),%xmm3        # 6493b8 <transformation_matrix+0x18>
  40b4ef:	movlhps %xmm6,%xmm11
  40b4f3:	unpcklps %xmm3,%xmm12
  40b4f7:	movlhps %xmm9,%xmm6
  40b4fb:	unpcklps %xmm7,%xmm3
  40b4fe:	movaps %xmm2,%xmm9
  40b502:	movss  %xmm0,-0x5c(%rsp)
  40b508:	unpcklps %xmm10,%xmm7
  40b50c:	movss  %xmm0,-0x4c(%rsp)
  40b512:	movaps %xmm8,%xmm10
  40b516:	movss  %xmm0,-0x44(%rsp)
  40b51c:	movss  0x23de9c(%rip),%xmm5        # 6493c0 <transformation_matrix+0x20>
  40b524:	movss  0x23dea4(%rip),%xmm4        # 6493d0 <transformation_matrix+0x30>
  40b52c:	movaps %xmm3,%xmm15
  40b530:	movss  %xmm0,-0x40(%rsp)
  40b536:	movss  %xmm0,-0x30(%rsp)
  40b53c:	movlhps %xmm12,%xmm15
  40b540:	movss  %xmm0,-0x2c(%rsp)
  40b546:	movlhps %xmm7,%xmm12
  40b54a:	movss  %xmm0,-0x24(%rsp)
  40b550:	movlhps %xmm3,%xmm7
  40b553:	movss  %xmm0,-0x1c(%rsp)
  40b559:	movss  %xmm0,-0x18(%rsp)
  40b55f:	movss  %xmm0,-0x14(%rsp)
  40b565:	movss  %xmm0,-0x10(%rsp)
  40b56b:	movss  %xmm0,-0xc(%rsp)
  40b571:	movss  0x23de4f(%rip),%xmm1        # 6493c8 <transformation_matrix+0x28>
  40b579:	movss  0x23de57(%rip),%xmm0        # 6493d8 <transformation_matrix+0x38>
  40b581:	unpcklps %xmm1,%xmm10
  40b585:	unpcklps %xmm0,%xmm9
  40b589:	unpcklps %xmm5,%xmm1
  40b58c:	unpcklps %xmm4,%xmm0
  40b58f:	unpcklps %xmm8,%xmm5
  40b593:	movaps %xmm1,%xmm13
  40b597:	unpcklps %xmm2,%xmm4
  40b59a:	movaps %xmm0,%xmm8
  40b59e:	movlhps %xmm10,%xmm13
  40b5a2:	movlhps %xmm5,%xmm10
  40b5a6:	movlhps %xmm9,%xmm8
  40b5aa:	movlhps %xmm1,%xmm5
  40b5ad:	movaps -0x68(%rsp),%xmm1
  40b5b2:	movlhps %xmm4,%xmm9
  40b5b6:	movaps %xmm8,-0x78(%rsp)
  40b5bc:	movlhps %xmm0,%xmm4
  40b5bf:	movaps %xmm1,%xmm8
  40b5c3:	movaps %xmm1,%xmm3
  40b5c6:	movaps -0x58(%rsp),%xmm0
  40b5cb:	shufps $0xc0,%xmm1,%xmm3
  40b5cf:	unpcklps %xmm0,%xmm8
  40b5d3:	movaps -0x48(%rsp),%xmm2
  40b5d8:	mulps  %xmm6,%xmm3
  40b5db:	shufps $0x6a,%xmm8,%xmm8
  40b5e0:	mulps  %xmm7,%xmm8
  40b5e4:	addps  %xmm8,%xmm3
  40b5e8:	movaps %xmm1,%xmm8
  40b5ec:	shufps $0xaf,%xmm0,%xmm1
  40b5f0:	shufps $0x4e,%xmm0,%xmm8
  40b5f5:	mulps  %xmm11,%xmm1
  40b5f9:	shufps $0xc0,%xmm8,%xmm8
  40b5fe:	mulps  %xmm5,%xmm8
  40b602:	addps  %xmm8,%xmm3
  40b606:	movaps %xmm0,%xmm8
  40b60a:	shufps $0x5,%xmm2,%xmm8
  40b60f:	addps  %xmm4,%xmm3
  40b612:	mulps  %xmm10,%xmm8
  40b616:	movaps %xmm3,0x23dc83(%rip)        # 6492a0 <out_invvertex>
  40b61d:	movaps %xmm0,%xmm3
  40b620:	shufps $0xf0,%xmm0,%xmm3
  40b624:	mulps  %xmm12,%xmm3
  40b628:	addps  %xmm3,%xmm1
  40b62b:	addps  %xmm8,%xmm1
  40b62f:	movaps -0x78(%rsp),%xmm8
  40b635:	addps  %xmm9,%xmm1
  40b639:	movaps %xmm1,0x23dc70(%rip)        # 6492b0 <out_invvertex+0x10>
  40b640:	movaps %xmm0,%xmm1
  40b643:	unpckhps %xmm2,%xmm0
  40b646:	shufps $0x4e,%xmm2,%xmm1
  40b64a:	shufps $0xfc,%xmm2,%xmm2
  40b64e:	shufps $0x56,%xmm0,%xmm0
  40b652:	shufps $0xfc,%xmm1,%xmm1
  40b656:	mulps  %xmm13,%xmm2
  40b65a:	mulps  %xmm14,%xmm1
  40b65e:	mulps  %xmm15,%xmm0
  40b662:	addps  %xmm1,%xmm0
  40b665:	movaps -0x18(%rsp),%xmm1
  40b66a:	addps  %xmm0,%xmm2
  40b66d:	movaps -0x28(%rsp),%xmm0
  40b672:	addps  %xmm8,%xmm2
  40b676:	movaps %xmm2,0x23dc43(%rip)        # 6492c0 <out_invvertex+0x20>
  40b67d:	movaps -0x38(%rsp),%xmm2
  40b682:	movaps %xmm2,%xmm3
  40b685:	unpcklps %xmm0,%xmm3
  40b688:	shufps $0x6a,%xmm3,%xmm3
  40b68c:	mulps  %xmm3,%xmm7
  40b68f:	movaps %xmm2,%xmm3
  40b692:	shufps $0xc0,%xmm2,%xmm3
  40b696:	mulps  %xmm3,%xmm6
  40b699:	addps  %xmm7,%xmm6
  40b69c:	movaps %xmm2,%xmm7
  40b69f:	shufps $0xaf,%xmm0,%xmm2
  40b6a3:	shufps $0x4e,%xmm0,%xmm7
  40b6a7:	mulps  %xmm2,%xmm11
  40b6ab:	shufps $0xc0,%xmm7,%xmm7
  40b6af:	mulps  %xmm7,%xmm5
  40b6b2:	addps  %xmm6,%xmm5
  40b6b5:	movaps %xmm0,%xmm6
  40b6b8:	shufps $0xf0,%xmm0,%xmm6
  40b6bc:	addps  %xmm5,%xmm4
  40b6bf:	movaps %xmm0,%xmm5
  40b6c2:	mulps  %xmm6,%xmm12
  40b6c6:	shufps $0x5,%xmm1,%xmm5
  40b6ca:	movaps %xmm4,0x23dbff(%rip)        # 6492d0 <out_invvertex+0x30>
  40b6d1:	movaps %xmm0,%xmm4
  40b6d4:	shufps $0x4e,%xmm1,%xmm0
  40b6d8:	addps  %xmm12,%xmm11
  40b6dc:	unpckhps %xmm1,%xmm4
  40b6df:	shufps $0xfc,%xmm1,%xmm1
  40b6e3:	shufps $0xfc,%xmm0,%xmm0
  40b6e7:	shufps $0x56,%xmm4,%xmm4
  40b6eb:	mulps  %xmm5,%xmm10
  40b6ef:	mulps  %xmm4,%xmm15
  40b6f3:	mulps  %xmm0,%xmm14
  40b6f7:	addps  %xmm11,%xmm10
  40b6fb:	mulps  %xmm1,%xmm13
  40b6ff:	addps  %xmm15,%xmm14
  40b703:	addps  %xmm10,%xmm9
  40b707:	addps  %xmm13,%xmm14
  40b70b:	movaps %xmm9,0x23dbcd(%rip)        # 6492e0 <out_invvertex+0x40>
  40b713:	addps  %xmm8,%xmm14
  40b717:	movaps %xmm14,0x23dbd1(%rip)        # 6492f0 <out_invvertex+0x50>
  40b71f:	retq   

000000000040b720 <Compute_Input_Unit_Vector>:
  40b720:	movss  0x23dcab(%rip),%xmm11        # 6493d4 <transformation_matrix+0x34>
  40b729:	movaps %xmm11,%xmm5
  40b72d:	movss  0x23dc9b(%rip),%xmm3        # 6493d0 <transformation_matrix+0x30>
  40b735:	movss  0x23dc9b(%rip),%xmm0        # 6493d8 <transformation_matrix+0x38>
  40b73d:	unpcklps %xmm0,%xmm5
  40b740:	movss  0x23dc5f(%rip),%xmm15        # 6493a8 <transformation_matrix+0x8>
  40b749:	unpcklps %xmm3,%xmm0
  40b74c:	unpcklps %xmm11,%xmm3
  40b750:	movss  0x23dc6c(%rip),%xmm1        # 6493c4 <transformation_matrix+0x24>
  40b758:	movss  0x23dc3f(%rip),%xmm10        # 6493a0 <transformation_matrix>
  40b761:	movaps %xmm0,%xmm13
  40b765:	movss  0x23dc36(%rip),%xmm8        # 6493a4 <transformation_matrix+0x4>
  40b76e:	movaps %xmm1,%xmm6
  40b771:	movlhps %xmm5,%xmm13
  40b775:	movlhps %xmm3,%xmm5
  40b778:	movlhps %xmm0,%xmm3
  40b77b:	movaps %xmm15,%xmm0
  40b77f:	movss  0x23dc39(%rip),%xmm4        # 6493c0 <transformation_matrix+0x20>
  40b787:	movss  0x23dc39(%rip),%xmm2        # 6493c8 <transformation_matrix+0x28>
  40b78f:	unpcklps %xmm10,%xmm0
  40b793:	movss  0x23dc14(%rip),%xmm9        # 6493b0 <transformation_matrix+0x10>
  40b79c:	unpcklps %xmm8,%xmm10
  40b7a0:	unpcklps %xmm2,%xmm6
  40b7a3:	movss  0x23dc09(%rip),%xmm7        # 6493b4 <transformation_matrix+0x14>
  40b7ab:	unpcklps %xmm4,%xmm2
  40b7ae:	movss  0x23dc01(%rip),%xmm11        # 6493b8 <transformation_matrix+0x18>
  40b7b7:	unpcklps %xmm1,%xmm4
  40b7ba:	unpcklps %xmm9,%xmm11
  40b7be:	unpcklps %xmm7,%xmm9
  40b7c2:	movaps %xmm10,%xmm12
  40b7c6:	movaps %xmm2,%xmm14
  40b7ca:	movlhps %xmm0,%xmm12
  40b7ce:	unpcklps %xmm15,%xmm8
  40b7d2:	movaps %xmm9,%xmm1
  40b7d6:	movlhps %xmm6,%xmm14
  40b7da:	movlhps %xmm4,%xmm6
  40b7dd:	movlhps %xmm2,%xmm4
  40b7e0:	pxor   %xmm2,%xmm2
  40b7e4:	movlhps %xmm11,%xmm1
  40b7e8:	mulps  0xe130(%rip),%xmm12        # 419920 <__dso_handle+0xb58>
  40b7f0:	movaps %xmm8,%xmm15
  40b7f4:	mulps  %xmm2,%xmm1
  40b7f7:	movlhps %xmm8,%xmm0
  40b7fb:	movlhps %xmm10,%xmm15
  40b7ff:	movaps 0xe129(%rip),%xmm10        # 419930 <__dso_handle+0xb68>
  40b807:	movaps %xmm4,%xmm8
  40b80b:	mulps  0xe13e(%rip),%xmm0        # 419950 <__dso_handle+0xb88>
  40b812:	addps  %xmm12,%xmm1
  40b816:	movss  0x23db99(%rip),%xmm12        # 6493b8 <transformation_matrix+0x18>
  40b81f:	mulps  %xmm15,%xmm10
  40b823:	unpcklps %xmm12,%xmm7
  40b827:	mulps  %xmm2,%xmm8
  40b82b:	movaps %xmm7,%xmm15
  40b82f:	movlhps %xmm7,%xmm11
  40b833:	movaps %xmm6,%xmm7
  40b836:	movlhps %xmm9,%xmm15
  40b83a:	movaps 0xe0fe(%rip),%xmm9        # 419940 <__dso_handle+0xb78>
  40b842:	addps  %xmm0,%xmm11
  40b846:	mulps  %xmm2,%xmm7
  40b849:	addps  %xmm1,%xmm8
  40b84d:	mulps  %xmm15,%xmm9
  40b851:	addps  %xmm4,%xmm1
  40b854:	mulps  %xmm14,%xmm2
  40b858:	addps  %xmm3,%xmm8
  40b85c:	addps  %xmm10,%xmm9
  40b860:	addps  %xmm11,%xmm2
  40b864:	movaps %xmm8,0x23d9d4(%rip)        # 649240 <uout_invvertex>
  40b86c:	addps  %xmm14,%xmm11
  40b870:	addps  %xmm9,%xmm7
  40b874:	addps  %xmm9,%xmm6
  40b878:	addps  %xmm13,%xmm2
  40b87c:	addps  %xmm5,%xmm7
  40b87f:	addps  %xmm1,%xmm3
  40b882:	movaps %xmm2,0x23d9d7(%rip)        # 649260 <uout_invvertex+0x20>
  40b889:	addps  %xmm6,%xmm5
  40b88c:	movaps %xmm7,0x23d9bd(%rip)        # 649250 <uout_invvertex+0x10>
  40b893:	addps  %xmm11,%xmm13
  40b897:	movaps %xmm3,0x23d9d2(%rip)        # 649270 <uout_invvertex+0x30>
  40b89e:	movaps %xmm5,0x23d9db(%rip)        # 649280 <uout_invvertex+0x40>
  40b8a5:	movaps %xmm13,0x23d9e3(%rip)        # 649290 <uout_invvertex+0x50>
  40b8ad:	retq   
  40b8ae:	xchg   %ax,%ax

000000000040b8b0 <Select_View>:
  40b8b0:	pxor   %xmm3,%xmm3
  40b8b4:	sub    $0x108,%rsp
  40b8bb:	pxor   %xmm2,%xmm2
  40b8bf:	movl   $0x3f800000,0xbc(%rsp)
  40b8ca:	pxor   %xmm1,%xmm1
  40b8ce:	movss  0xe099(%rip),%xmm11        # 419970 <__dso_handle+0xba8>
  40b8d7:	cvtss2sd 0x23da81(%rip),%xmm3        # 649360 <out_diag_len>
  40b8df:	pxor   %xmm5,%xmm5
  40b8e3:	cvtss2sd 0x23da79(%rip),%xmm2        # 649364 <out_diag_len+0x4>
  40b8eb:	pxor   %xmm4,%xmm4
  40b8ef:	cvtss2sd 0x23da71(%rip),%xmm1        # 649368 <out_diag_len+0x8>
  40b8f7:	mulsd  0xdd59(%rip),%xmm3        # 419658 <__dso_handle+0x890>
  40b8ff:	mulsd  0xdd51(%rip),%xmm2        # 419658 <__dso_handle+0x890>
  40b907:	movaps %xmm11,%xmm12
  40b90b:	mulsd  0xdd45(%rip),%xmm1        # 419658 <__dso_handle+0x890>
  40b913:	pxor   %xmm6,%xmm6
  40b917:	movaps 0xe041(%rip),%xmm10        # 419960 <__dso_handle+0xb98>
  40b91f:	pxor   %xmm14,%xmm14
  40b924:	movaps %xmm10,%xmm9
  40b928:	movaps %xmm10,%xmm13
  40b92c:	cvtsd2ss %xmm3,%xmm5
  40b930:	cvtsd2ss %xmm2,%xmm4
  40b934:	cvtsd2ss %xmm1,%xmm6
  40b938:	movaps %xmm10,%xmm8
  40b93c:	movss  %xmm5,0xb0(%rsp)
  40b945:	movss  %xmm4,0xb4(%rsp)
  40b94e:	movss  %xmm6,0xb8(%rsp)
  40b957:	movaps 0xb0(%rsp),%xmm7
  40b95f:	shufps $0xdd,%xmm7,%xmm9
  40b964:	shufps $0x88,%xmm7,%xmm8
  40b969:	shufps $0x88,%xmm9,%xmm13
  40b96e:	shufps $0x88,%xmm8,%xmm12
  40b973:	shufps $0xdd,%xmm8,%xmm11
  40b978:	movaps %xmm13,%xmm15
  40b97c:	shufps $0xdd,%xmm9,%xmm10
  40b981:	mulps  %xmm14,%xmm15
  40b985:	movaps %xmm11,%xmm3
  40b989:	movaps %xmm10,%xmm2
  40b98d:	mulps  %xmm14,%xmm3
  40b991:	movaps %xmm15,%xmm5
  40b995:	mulps  %xmm14,%xmm2
  40b999:	addps  %xmm12,%xmm5
  40b99d:	mulps  %xmm14,%xmm12
  40b9a1:	addps  %xmm3,%xmm5
  40b9a4:	addps  %xmm12,%xmm13
  40b9a8:	addps  %xmm15,%xmm12
  40b9ac:	addps  %xmm2,%xmm5
  40b9af:	addps  %xmm3,%xmm13
  40b9b3:	addps  %xmm12,%xmm11
  40b9b7:	movaps %xmm5,%xmm4
  40b9ba:	addps  %xmm3,%xmm12
  40b9be:	addps  %xmm2,%xmm13
  40b9c2:	addps  %xmm2,%xmm11
  40b9c6:	addps  %xmm12,%xmm10
  40b9ca:	movaps %xmm13,%xmm7
  40b9ce:	unpcklps %xmm11,%xmm4
  40b9d2:	unpckhps %xmm11,%xmm5
  40b9d6:	unpcklps %xmm10,%xmm7
  40b9da:	movaps %xmm4,%xmm1
  40b9dd:	unpckhps %xmm10,%xmm13
  40b9e1:	movaps %xmm5,%xmm10
  40b9e5:	unpcklps %xmm7,%xmm1
  40b9e8:	movaps %xmm5,%xmm6
  40b9eb:	unpckhps %xmm7,%xmm4
  40b9ee:	unpcklps %xmm13,%xmm10
  40b9f2:	movaps %xmm1,0xc0(%rsp)
  40b9fa:	unpckhps %xmm13,%xmm6
  40b9fe:	movaps %xmm4,0xd0(%rsp)
  40ba06:	movaps %xmm10,0xe0(%rsp)
  40ba0f:	movaps %xmm6,0xf0(%rsp)
  40ba17:	movss  0xc4(%rsp),%xmm11
  40ba21:	movss  0xc0(%rsp),%xmm1
  40ba2a:	unpcklps %xmm11,%xmm1
  40ba2e:	movss  0xcc(%rsp),%xmm8
  40ba38:	movss  0xc8(%rsp),%xmm2
  40ba41:	unpcklps %xmm8,%xmm2
  40ba45:	movss  0xd4(%rsp),%xmm5
  40ba4e:	movaps %xmm1,%xmm12
  40ba52:	movss  0xdc(%rsp),%xmm13
  40ba5c:	movlhps %xmm2,%xmm12
  40ba60:	movss  0xd0(%rsp),%xmm2
  40ba69:	unpcklps %xmm5,%xmm2
  40ba6c:	movss  0xd8(%rsp),%xmm3
  40ba75:	unpcklps %xmm13,%xmm3
  40ba79:	movss  0xe4(%rsp),%xmm9
  40ba83:	movaps %xmm2,%xmm10
  40ba87:	movss  0xec(%rsp),%xmm4
  40ba90:	movlhps %xmm3,%xmm10
  40ba94:	movss  0xe0(%rsp),%xmm3
  40ba9d:	unpcklps %xmm9,%xmm3
  40baa1:	movaps %xmm10,%xmm15
  40baa5:	movss  0xe8(%rsp),%xmm6
  40baae:	unpcklps %xmm4,%xmm6
  40bab1:	mulps  %xmm14,%xmm15
  40bab5:	movaps %xmm3,%xmm2
  40bab8:	movss  0xfc(%rsp),%xmm7
  40bac1:	movlhps %xmm6,%xmm2
  40bac4:	movss  0xf8(%rsp),%xmm6
  40bacd:	movss  0xf4(%rsp),%xmm1
  40bad6:	movss  0xf0(%rsp),%xmm4
  40badf:	unpcklps %xmm7,%xmm6
  40bae2:	movaps %xmm15,%xmm9
  40bae6:	unpcklps %xmm1,%xmm4
  40bae9:	movaps %xmm2,%xmm5
  40baec:	addps  %xmm12,%xmm9
  40baf0:	mulps  %xmm14,%xmm12
  40baf4:	movaps %xmm4,%xmm13
  40baf8:	mulps  %xmm14,%xmm5
  40bafc:	movlhps %xmm6,%xmm13
  40bb00:	addps  %xmm12,%xmm10
  40bb04:	movaps %xmm13,%xmm8
  40bb08:	addps  %xmm15,%xmm12
  40bb0c:	mulps  %xmm14,%xmm8
  40bb10:	movaps %xmm2,%xmm14
  40bb14:	addps  %xmm5,%xmm9
  40bb18:	addps  %xmm5,%xmm10
  40bb1c:	addps  %xmm12,%xmm14
  40bb20:	addps  %xmm5,%xmm12
  40bb24:	addps  %xmm8,%xmm9
  40bb28:	addps  %xmm8,%xmm10
  40bb2c:	addps  %xmm8,%xmm14
  40bb30:	movaps %xmm9,0xc0(%rsp)
  40bb39:	addps  %xmm13,%xmm12
  40bb3d:	movaps %xmm10,0xd0(%rsp)
  40bb46:	movaps %xmm14,0xe0(%rsp)
  40bb4f:	movaps %xmm12,0xf0(%rsp)
  40bb58:	movss  0xe4(%rsp),%xmm10
  40bb62:	movss  0xc0(%rsp),%xmm2
  40bb6b:	movss  0xc4(%rsp),%xmm4
  40bb74:	movss  0xc8(%rsp),%xmm13
  40bb7e:	movss  0xcc(%rsp),%xmm15
  40bb88:	movss  0xd0(%rsp),%xmm3
  40bb91:	movss  0xd4(%rsp),%xmm11
  40bb9b:	movss  0xd8(%rsp),%xmm7
  40bba4:	movss  0xdc(%rsp),%xmm12
  40bbae:	movss  0xe0(%rsp),%xmm1
  40bbb7:	movss  0xe8(%rsp),%xmm6
  40bbc0:	movss  0xec(%rsp),%xmm8
  40bbca:	movss  0xf0(%rsp),%xmm5
  40bbd3:	movss  %xmm10,0x4(%rsp)
  40bbda:	movss  %xmm10,0x23d761(%rip)        # 649344 <invmatrix+0x24>
  40bbe3:	movss  %xmm2,0x23d735(%rip)        # 649320 <invmatrix>
  40bbeb:	movss  %xmm4,0x23d731(%rip)        # 649324 <invmatrix+0x4>
  40bbf3:	movss  %xmm13,0x23d72c(%rip)        # 649328 <invmatrix+0x8>
  40bbfc:	movss  %xmm15,0x23d727(%rip)        # 64932c <invmatrix+0xc>
  40bc05:	movss  %xmm3,0x23d723(%rip)        # 649330 <invmatrix+0x10>
  40bc0d:	movss  %xmm11,0x23d71e(%rip)        # 649334 <invmatrix+0x14>
  40bc16:	movss  %xmm7,0x23d71a(%rip)        # 649338 <invmatrix+0x18>
  40bc1e:	movss  %xmm12,0x23d715(%rip)        # 64933c <invmatrix+0x1c>
  40bc27:	movss  %xmm1,0x23d711(%rip)        # 649340 <invmatrix+0x20>
  40bc2f:	movss  %xmm6,0x23d711(%rip)        # 649348 <invmatrix+0x28>
  40bc37:	movss  %xmm8,0x23d70c(%rip)        # 64934c <invmatrix+0x2c>
  40bc40:	movss  %xmm5,0x8(%rsp)
  40bc46:	cmpq   $0x0,0x2386d2(%rip)        # 644320 <frame>
  40bc4e:	movss  0xf4(%rsp),%xmm9
  40bc58:	movss  0xf8(%rsp),%xmm14
  40bc62:	movss  0xfc(%rsp),%xmm10
  40bc6c:	movss  %xmm5,0x23d6dc(%rip)        # 649350 <invmatrix+0x30>
  40bc74:	movss  %xmm9,0xc(%rsp)
  40bc7b:	movss  %xmm9,0x23d6d0(%rip)        # 649354 <invmatrix+0x34>
  40bc84:	movss  %xmm14,0x23d6cb(%rip)        # 649358 <invmatrix+0x38>
  40bc8d:	movss  %xmm10,0x23d6c6(%rip)        # 64935c <invmatrix+0x3c>
  40bc96:	je     40bcae <Select_View+0x3fe>
  40bc98:	cvtsd2ss %xmm0,%xmm0
  40bc9c:	addss  0x6451a8(,%rdi,4),%xmm0
  40bca5:	movss  %xmm0,0x6451a8(,%rdi,4)
  40bcae:	movss  %xmm2,0x30(%rsp)
  40bcb4:	movss  0xd144(%rip),%xmm2        # 418e00 <__dso_handle+0x38>
  40bcbc:	lea    0x70(%rsp),%rsi
  40bcc1:	movss  %xmm4,0x20(%rsp)
  40bcc7:	pxor   %xmm0,%xmm0
  40bccb:	movss  0x2394d5(%rip),%xmm4        # 6451a8 <angle>
  40bcd3:	lea    0x78(%rsp),%rdi
  40bcd8:	xorps  %xmm2,%xmm4
  40bcdb:	movss  %xmm10,0x5c(%rsp)
  40bce2:	movss  %xmm14,0x58(%rsp)
  40bce9:	movl   $0x0,0x90(%rsp)
  40bcf4:	movq   $0x0,0x9c(%rsp)
  40bd00:	movss  %xmm8,0x54(%rsp)
  40bd07:	movq   $0x0,0xac(%rsp)
  40bd13:	cvtss2sd %xmm4,%xmm0
  40bd17:	movq   $0x0,0xb4(%rsp)
  40bd23:	movss  %xmm6,0x50(%rsp)
  40bd29:	movl   $0x3f800000,0xbc(%rsp)
  40bd34:	divsd  0xdbd4(%rip),%xmm0        # 419910 <__dso_handle+0xb48>
  40bd3c:	movss  %xmm1,0x4c(%rsp)
  40bd42:	movss  %xmm12,0x48(%rsp)
  40bd49:	movss  %xmm7,0x44(%rsp)
  40bd4f:	movss  %xmm11,0x40(%rsp)
  40bd56:	movss  %xmm3,0x3c(%rsp)
  40bd5c:	movss  %xmm15,0x38(%rsp)
  40bd63:	movss  %xmm13,0x34(%rsp)
  40bd6a:	movaps %xmm2,0x10(%rsp)
  40bd6f:	mulsd  0xdba1(%rip),%xmm0        # 419918 <__dso_handle+0xb50>
  40bd77:	callq  4011e0 <sincos@plt>
  40bd7c:	movss  0x48(%rsp),%xmm12
  40bd83:	lea    0x70(%rsp),%rsi
  40bd88:	movss  0x40(%rsp),%xmm6
  40bd8e:	lea    0x78(%rsp),%rdi
  40bd93:	movss  0x44(%rsp),%xmm1
  40bd99:	movss  0x3c(%rsp),%xmm2
  40bd9f:	unpcklps %xmm12,%xmm1
  40bda3:	movss  0x38(%rsp),%xmm11
  40bdaa:	movss  0x20(%rsp),%xmm7
  40bdb0:	unpcklps %xmm6,%xmm2
  40bdb3:	movss  0x34(%rsp),%xmm3
  40bdb9:	movss  0x30(%rsp),%xmm14
  40bdc0:	unpcklps %xmm11,%xmm3
  40bdc4:	unpcklps %xmm7,%xmm14
  40bdc8:	pxor   %xmm15,%xmm15
  40bdcd:	movaps 0x10(%rsp),%xmm4
  40bdd2:	movlhps %xmm1,%xmm2
  40bdd5:	movlhps %xmm3,%xmm14
  40bdd9:	movss  0x54(%rsp),%xmm5
  40bddf:	pxor   %xmm3,%xmm3
  40bde3:	cvtsd2ss 0x78(%rsp),%xmm15
  40bdea:	movss  %xmm15,0x98(%rsp)
  40bdf4:	movss  0x4(%rsp),%xmm9
  40bdfb:	xorps  %xmm4,%xmm15
  40bdff:	movss  0x50(%rsp),%xmm8
  40be06:	movss  0x4c(%rsp),%xmm10
  40be0d:	unpcklps %xmm5,%xmm8
  40be11:	movaps %xmm2,%xmm1
  40be14:	unpcklps %xmm9,%xmm10
  40be18:	movss  %xmm15,0xa4(%rsp)
  40be22:	pxor   %xmm13,%xmm13
  40be27:	movss  0xc(%rsp),%xmm15
  40be2e:	mulps  %xmm3,%xmm1
  40be31:	movss  0x8(%rsp),%xmm7
  40be37:	movlhps %xmm8,%xmm10
  40be3b:	unpcklps %xmm15,%xmm7
  40be3f:	cvtsd2ss 0x70(%rsp),%xmm13
  40be46:	movss  0x5c(%rsp),%xmm0
  40be4c:	movss  %xmm13,0x94(%rsp)
  40be56:	movaps %xmm10,%xmm12
  40be5a:	movss  %xmm13,0xa8(%rsp)
  40be64:	movaps %xmm7,%xmm11
  40be68:	movss  0x58(%rsp),%xmm13
  40be6f:	unpcklps %xmm0,%xmm13
  40be73:	addps  %xmm14,%xmm1
  40be77:	mulps  %xmm3,%xmm12
  40be7b:	movaps 0x90(%rsp),%xmm5
  40be83:	movlhps %xmm13,%xmm11
  40be87:	movaps 0xa0(%rsp),%xmm7
  40be8f:	movaps %xmm5,%xmm9
  40be93:	movaps %xmm11,%xmm6
  40be97:	addps  %xmm12,%xmm1
  40be9b:	movaps %xmm5,%xmm8
  40be9f:	mulps  %xmm3,%xmm6
  40bea2:	movaps %xmm7,%xmm0
  40bea5:	movaps %xmm7,%xmm15
  40bea9:	shufps $0x55,%xmm5,%xmm9
  40beae:	shufps $0x0,%xmm5,%xmm8
  40beb3:	shufps $0x55,%xmm7,%xmm0
  40beb7:	movaps %xmm5,%xmm13
  40bebb:	addps  %xmm6,%xmm1
  40bebe:	shufps $0x0,%xmm7,%xmm15
  40bec3:	mulps  %xmm14,%xmm8
  40bec7:	movaps %xmm3,0x60(%rsp)
  40becc:	mulps  %xmm14,%xmm15
  40bed0:	movaps %xmm1,0xc0(%rsp)
  40bed8:	mulps  %xmm2,%xmm9
  40bedc:	movaps %xmm7,%xmm3
  40bedf:	mulps  %xmm2,%xmm0
  40bee2:	movaps 0xb0(%rsp),%xmm1
  40beea:	shufps $0xaa,%xmm5,%xmm13
  40beef:	movaps %xmm1,%xmm12
  40bef3:	movaps %xmm1,%xmm6
  40bef6:	shufps $0xaa,%xmm7,%xmm3
  40befa:	shufps $0x55,%xmm1,%xmm12
  40beff:	addps  %xmm8,%xmm9
  40bf03:	shufps $0x0,%xmm1,%xmm6
  40bf07:	mulps  %xmm10,%xmm13
  40bf0b:	addps  %xmm15,%xmm0
  40bf0f:	mulps  %xmm12,%xmm2
  40bf13:	mulps  %xmm6,%xmm14
  40bf17:	addps  %xmm13,%xmm9
  40bf1b:	mulps  %xmm10,%xmm3
  40bf1f:	shufps $0xff,%xmm5,%xmm5
  40bf23:	addps  %xmm2,%xmm14
  40bf27:	movaps %xmm1,%xmm2
  40bf2a:	shufps $0xff,%xmm7,%xmm7
  40bf2e:	shufps $0xaa,%xmm1,%xmm2
  40bf32:	addps  %xmm3,%xmm0
  40bf35:	shufps $0xff,%xmm1,%xmm1
  40bf39:	mulps  %xmm11,%xmm5
  40bf3d:	mulps  %xmm2,%xmm10
  40bf41:	mulps  %xmm11,%xmm7
  40bf45:	addps  %xmm9,%xmm5
  40bf49:	mulps  %xmm11,%xmm1
  40bf4d:	addps  %xmm14,%xmm10
  40bf51:	movss  0xc0(%rsp),%xmm14
  40bf5b:	addps  %xmm0,%xmm7
  40bf5e:	movaps %xmm5,0xd0(%rsp)
  40bf66:	addps  %xmm10,%xmm1
  40bf6a:	movaps %xmm7,0xe0(%rsp)
  40bf72:	movaps %xmm1,0xf0(%rsp)
  40bf7a:	movss  %xmm14,0x5c(%rsp)
  40bf81:	movaps %xmm4,0x20(%rsp)
  40bf86:	movss  0xc4(%rsp),%xmm10
  40bf90:	movss  0xe0(%rsp),%xmm0
  40bf99:	movss  %xmm10,0x58(%rsp)
  40bfa0:	movss  0x239203(%rip),%xmm10        # 6451ac <angle+0x4>
  40bfa9:	xorps  %xmm4,%xmm10
  40bfad:	movss  %xmm0,0x3c(%rsp)
  40bfb3:	pxor   %xmm0,%xmm0
  40bfb7:	movss  0xc8(%rsp),%xmm11
  40bfc1:	movss  0xcc(%rsp),%xmm5
  40bfca:	movss  0xd0(%rsp),%xmm9
  40bfd4:	cvtss2sd %xmm10,%xmm0
  40bfd9:	movss  0xd4(%rsp),%xmm8
  40bfe3:	movss  0xd8(%rsp),%xmm13
  40bfed:	movss  0xdc(%rsp),%xmm7
  40bff6:	movss  0xe4(%rsp),%xmm15
  40c000:	movss  0xe8(%rsp),%xmm3
  40c009:	movss  0xec(%rsp),%xmm1
  40c012:	movss  0xf0(%rsp),%xmm12
  40c01c:	movss  0xf4(%rsp),%xmm6
  40c025:	movss  0xf8(%rsp),%xmm2
  40c02e:	movss  0xfc(%rsp),%xmm14
  40c038:	movss  %xmm11,0x54(%rsp)
  40c03f:	movss  %xmm5,0x50(%rsp)
  40c045:	movss  %xmm9,0x4c(%rsp)
  40c04c:	movss  %xmm8,0x48(%rsp)
  40c053:	movss  %xmm13,0x44(%rsp)
  40c05a:	movss  %xmm7,0x40(%rsp)
  40c060:	movss  %xmm15,0x4(%rsp)
  40c067:	movss  %xmm3,0x38(%rsp)
  40c06d:	movss  %xmm1,0x34(%rsp)
  40c073:	movss  %xmm12,0x8(%rsp)
  40c07a:	movss  %xmm6,0xc(%rsp)
  40c080:	movss  %xmm2,0x10(%rsp)
  40c086:	movss  %xmm14,0x30(%rsp)
  40c08d:	movl   $0x0,0x84(%rsp)
  40c098:	divsd  0xd870(%rip),%xmm0        # 419910 <__dso_handle+0xb48>
  40c0a0:	movq   $0x0,0x8c(%rsp)
  40c0ac:	movq   $0x3f800000,0x94(%rsp)
  40c0b8:	movl   $0x0,0x9c(%rsp)
  40c0c3:	movl   $0x0,0xa4(%rsp)
  40c0ce:	movq   $0x0,0xac(%rsp)
  40c0da:	movq   $0x0,0xb4(%rsp)
  40c0e6:	movl   $0x3f800000,0xbc(%rsp)
  40c0f1:	mulsd  0xd81f(%rip),%xmm0        # 419918 <__dso_handle+0xb50>
  40c0f9:	callq  4011e0 <sincos@plt>
  40c0fe:	pxor   %xmm5,%xmm5
  40c102:	movaps 0x20(%rsp),%xmm4
  40c107:	pxor   %xmm11,%xmm11
  40c10c:	cvtsd2ss 0x78(%rsp),%xmm5
  40c112:	movaps %xmm5,%xmm9
  40c116:	movss  %xmm5,0xa0(%rsp)
  40c11f:	movss  0x40(%rsp),%xmm0
  40c125:	cvtsd2ss 0x70(%rsp),%xmm11
  40c12c:	xorps  %xmm4,%xmm9
  40c130:	movss  0x48(%rsp),%xmm3
  40c136:	movss  0x44(%rsp),%xmm15
  40c13d:	movss  0x4c(%rsp),%xmm12
  40c144:	unpcklps %xmm0,%xmm15
  40c148:	unpcklps %xmm3,%xmm12
  40c14c:	movss  %xmm11,0x80(%rsp)
  40c156:	movss  %xmm9,0x88(%rsp)
  40c160:	movss  0x50(%rsp),%xmm8
  40c167:	movlhps %xmm15,%xmm12
  40c16b:	movss  0x58(%rsp),%xmm7
  40c171:	movaps 0x80(%rsp),%xmm15
  40c17a:	movss  0x54(%rsp),%xmm13
  40c181:	movss  0x5c(%rsp),%xmm1
  40c187:	unpcklps %xmm8,%xmm13
  40c18b:	unpcklps %xmm7,%xmm1
  40c18e:	movss  %xmm11,0xa8(%rsp)
  40c198:	movaps %xmm15,%xmm0
  40c19c:	movaps %xmm15,%xmm7
  40c1a0:	movss  0x34(%rsp),%xmm6
  40c1a6:	shufps $0x0,%xmm15,%xmm0
  40c1ab:	shufps $0x55,%xmm15,%xmm7
  40c1b0:	movlhps %xmm13,%xmm1
  40c1b4:	movss  0x4(%rsp),%xmm14
  40c1bb:	movss  0x38(%rsp),%xmm2
  40c1c1:	mulps  %xmm1,%xmm0
  40c1c4:	movss  0x3c(%rsp),%xmm10
  40c1cb:	unpcklps %xmm6,%xmm2
  40c1ce:	movaps %xmm15,%xmm3
  40c1d2:	mulps  %xmm12,%xmm7
  40c1d6:	movss  0xc(%rsp),%xmm8
  40c1dd:	unpcklps %xmm14,%xmm10
  40c1e1:	movss  0x8(%rsp),%xmm9
  40c1e8:	shufps $0xaa,%xmm15,%xmm3
  40c1ed:	unpcklps %xmm8,%xmm9
  40c1f1:	movss  0x30(%rsp),%xmm5
  40c1f7:	movlhps %xmm2,%xmm10
  40c1fb:	movss  0x10(%rsp),%xmm11
  40c202:	addps  %xmm7,%xmm0
  40c205:	unpcklps %xmm5,%xmm11
  40c209:	mulps  %xmm10,%xmm3
  40c20d:	movaps %xmm9,%xmm13
  40c211:	movaps 0x90(%rsp),%xmm6
  40c219:	shufps $0xff,%xmm15,%xmm15
  40c21e:	movlhps %xmm11,%xmm13
  40c222:	movaps 0xa0(%rsp),%xmm5
  40c22a:	movaps %xmm6,%xmm2
  40c22d:	movaps %xmm6,%xmm14
  40c231:	addps  %xmm3,%xmm0
  40c234:	mulps  %xmm13,%xmm15
  40c238:	movaps %xmm5,%xmm9
  40c23c:	movaps %xmm5,%xmm8
  40c240:	shufps $0x55,%xmm6,%xmm2
  40c244:	shufps $0x0,%xmm6,%xmm14
  40c249:	shufps $0x55,%xmm5,%xmm9
  40c24e:	movaps %xmm6,%xmm11
  40c252:	addps  %xmm0,%xmm15
  40c256:	movaps 0xb0(%rsp),%xmm0
  40c25e:	shufps $0x0,%xmm5,%xmm8
  40c263:	mulps  %xmm1,%xmm14
  40c267:	movaps %xmm0,%xmm7
  40c26a:	movaps %xmm0,%xmm3
  40c26d:	mulps  %xmm1,%xmm8
  40c271:	movaps %xmm15,0xc0(%rsp)
  40c27a:	shufps $0x55,%xmm0,%xmm7
  40c27e:	shufps $0x0,%xmm0,%xmm3
  40c282:	movaps %xmm5,%xmm15
  40c286:	mulps  %xmm12,%xmm2
  40c28a:	mulps  %xmm12,%xmm9
  40c28e:	mulps  %xmm3,%xmm1
  40c291:	addps  %xmm14,%xmm2
  40c295:	mulps  %xmm7,%xmm12
  40c299:	addps  %xmm8,%xmm9
  40c29d:	shufps $0xaa,%xmm6,%xmm11
  40c2a2:	shufps $0xaa,%xmm5,%xmm15
  40c2a7:	shufps $0xff,%xmm6,%xmm6
  40c2ab:	addps  %xmm12,%xmm1
  40c2af:	movaps %xmm0,%xmm12
  40c2b3:	mulps  %xmm10,%xmm11
  40c2b7:	shufps $0xaa,%xmm0,%xmm12
  40c2bc:	mulps  %xmm10,%xmm15
  40c2c0:	mulps  %xmm12,%xmm10
  40c2c4:	addps  %xmm11,%xmm2
  40c2c8:	shufps $0xff,%xmm5,%xmm5
  40c2cc:	shufps $0xff,%xmm0,%xmm0
  40c2d0:	addps  %xmm15,%xmm9
  40c2d4:	mulps  %xmm13,%xmm6
  40c2d8:	addps  %xmm1,%xmm10
  40c2dc:	movss  0xcc(%rsp),%xmm1
  40c2e5:	mulps  %xmm13,%xmm5
  40c2e9:	mulps  %xmm13,%xmm0
  40c2ed:	addps  %xmm2,%xmm6
  40c2f0:	addps  %xmm9,%xmm5
  40c2f4:	addps  %xmm10,%xmm0
  40c2f8:	movaps %xmm6,0xd0(%rsp)
  40c300:	movaps %xmm5,0xe0(%rsp)
  40c308:	movaps %xmm0,0xf0(%rsp)
  40c310:	movss  0xc8(%rsp),%xmm10
  40c31a:	movl   $0x3f800000,0xbc(%rsp)
  40c325:	movss  0xc4(%rsp),%xmm6
  40c32e:	movss  0xc0(%rsp),%xmm0
  40c337:	unpcklps %xmm1,%xmm10
  40c33b:	unpcklps %xmm6,%xmm0
  40c33e:	movss  0xd4(%rsp),%xmm9
  40c348:	movss  0xd0(%rsp),%xmm1
  40c351:	movaps %xmm10,%xmm13
  40c355:	unpcklps %xmm9,%xmm1
  40c359:	movss  0xdc(%rsp),%xmm2
  40c362:	movaps %xmm0,%xmm14
  40c366:	movss  0xd8(%rsp),%xmm0
  40c36f:	unpcklps %xmm2,%xmm0
  40c372:	movaps %xmm1,%xmm15
  40c376:	movss  0xec(%rsp),%xmm8
  40c380:	movaps 0x60(%rsp),%xmm5
  40c385:	movlhps %xmm13,%xmm14
  40c389:	movlhps %xmm0,%xmm15
  40c38d:	movss  0xe8(%rsp),%xmm0
  40c396:	movss  0xe4(%rsp),%xmm3
  40c39f:	unpcklps %xmm8,%xmm0
  40c3a3:	movss  0xe0(%rsp),%xmm2
  40c3ac:	movaps %xmm15,%xmm8
  40c3b0:	unpcklps %xmm3,%xmm2
  40c3b3:	movss  0xfc(%rsp),%xmm13
  40c3bd:	mulps  %xmm5,%xmm8
  40c3c1:	movss  0xf4(%rsp),%xmm6
  40c3ca:	movaps %xmm2,%xmm12
  40c3ce:	movss  0xf8(%rsp),%xmm3
  40c3d7:	movlhps %xmm0,%xmm12
  40c3db:	movss  0xf0(%rsp),%xmm0
  40c3e4:	unpcklps %xmm13,%xmm3
  40c3e8:	unpcklps %xmm6,%xmm0
  40c3eb:	movaps %xmm8,%xmm11
  40c3ef:	movaps %xmm15,%xmm13
  40c3f3:	mulps  0xd5a5(%rip),%xmm15        # 4199a0 <__dso_handle+0xbd8>
  40c3fb:	addps  %xmm14,%xmm11
  40c3ff:	movaps 0xd57a(%rip),%xmm2        # 419980 <__dso_handle+0xbb8>
  40c406:	mulps  %xmm5,%xmm14
  40c40a:	movaps %xmm0,%xmm1
  40c40d:	movaps %xmm12,%xmm7
  40c411:	movlhps %xmm3,%xmm1
  40c414:	movaps 0xd575(%rip),%xmm3        # 419990 <__dso_handle+0xbc8>
  40c41b:	mulps  %xmm2,%xmm13
  40c41f:	movaps %xmm1,%xmm9
  40c423:	mulps  %xmm12,%xmm3
  40c427:	addps  %xmm14,%xmm15
  40c42b:	mulps  %xmm2,%xmm12
  40c42f:	addps  %xmm14,%xmm13
  40c433:	mulps  %xmm5,%xmm9
  40c437:	addps  %xmm8,%xmm14
  40c43b:	mulps  %xmm5,%xmm7
  40c43e:	addps  %xmm12,%xmm15
  40c442:	pxor   %xmm12,%xmm12
  40c447:	addps  %xmm3,%xmm13
  40c44b:	addps  %xmm7,%xmm11
  40c44f:	addps  %xmm9,%xmm15
  40c453:	addps  %xmm7,%xmm14
  40c457:	addps  %xmm9,%xmm11
  40c45b:	movaps %xmm15,0xe0(%rsp)
  40c464:	addps  %xmm9,%xmm13
  40c468:	addps  %xmm1,%xmm14
  40c46c:	movss  0x23ce93(%rip),%xmm15        # 649308 <out_diag_length>
  40c475:	xorps  %xmm4,%xmm15
  40c479:	pxor   %xmm4,%xmm4
  40c47d:	movaps %xmm11,0xc0(%rsp)
  40c486:	cvtss2sd %xmm15,%xmm4
  40c48b:	movaps %xmm13,0xd0(%rsp)
  40c494:	mulsd  0xd1bc(%rip),%xmm4        # 419658 <__dso_handle+0x890>
  40c49c:	movaps %xmm14,0xf0(%rsp)
  40c4a5:	movss  0xcc(%rsp),%xmm10
  40c4af:	cvtsd2ss %xmm4,%xmm12
  40c4b4:	movss  0xc4(%rsp),%xmm6
  40c4bd:	movss  0xc8(%rsp),%xmm2
  40c4c6:	unpcklps %xmm10,%xmm2
  40c4ca:	movss  %xmm12,0xb0(%rsp)
  40c4d4:	movss  %xmm12,0xb4(%rsp)
  40c4de:	movss  %xmm12,0xb8(%rsp)
  40c4e8:	movss  0xc0(%rsp),%xmm3
  40c4f1:	unpcklps %xmm6,%xmm3
  40c4f4:	movss  0xdc(%rsp),%xmm1
  40c4fd:	movss  0xd4(%rsp),%xmm8
  40c507:	movss  0xe4(%rsp),%xmm15
  40c511:	movaps %xmm3,%xmm11
  40c515:	movss  0xf4(%rsp),%xmm0
  40c51e:	movss  0xf0(%rsp),%xmm3
  40c527:	movlhps %xmm2,%xmm11
  40c52b:	movss  0xd8(%rsp),%xmm2
  40c534:	unpcklps %xmm1,%xmm2
  40c537:	movss  0xd0(%rsp),%xmm1
  40c540:	unpcklps %xmm0,%xmm3
  40c543:	unpcklps %xmm8,%xmm1
  40c547:	movss  0xec(%rsp),%xmm9
  40c551:	movss  0xfc(%rsp),%xmm10
  40c55b:	movaps %xmm3,%xmm13
  40c55f:	movaps %xmm1,%xmm14
  40c563:	movss  0xe8(%rsp),%xmm4
  40c56c:	movlhps %xmm2,%xmm14
  40c570:	movss  0xe0(%rsp),%xmm2
  40c579:	unpcklps %xmm15,%xmm2
  40c57d:	movss  0xf8(%rsp),%xmm1
  40c586:	unpcklps %xmm9,%xmm4
  40c58a:	unpcklps %xmm10,%xmm1
  40c58e:	movaps %xmm2,%xmm12
  40c592:	movaps %xmm14,%xmm8
  40c596:	movaps 0xb0(%rsp),%xmm10
  40c59f:	movlhps %xmm4,%xmm12
  40c5a3:	movlhps %xmm1,%xmm13
  40c5a7:	mulps  %xmm5,%xmm8
  40c5ab:	movaps %xmm12,%xmm9
  40c5af:	movaps %xmm13,%xmm15
  40c5b3:	movaps %xmm10,%xmm1
  40c5b7:	mulps  %xmm5,%xmm9
  40c5bb:	mulps  %xmm5,%xmm15
  40c5bf:	movaps %xmm8,%xmm4
  40c5c3:	mulps  %xmm11,%xmm5
  40c5c7:	addps  %xmm11,%xmm4
  40c5cb:	shufps $0x55,%xmm10,%xmm1
  40c5d0:	movaps %xmm5,%xmm2
  40c5d3:	mulps  %xmm14,%xmm1
  40c5d7:	addps  %xmm8,%xmm5
  40c5db:	addps  %xmm14,%xmm2
  40c5df:	movaps %xmm10,%xmm14
  40c5e3:	addps  %xmm9,%xmm4
  40c5e7:	shufps $0x0,%xmm10,%xmm14
  40c5ec:	addps  %xmm12,%xmm5
  40c5f0:	mulps  %xmm14,%xmm11
  40c5f4:	addps  %xmm9,%xmm2
  40c5f8:	addps  %xmm15,%xmm4
  40c5fc:	addps  %xmm11,%xmm1
  40c600:	movaps %xmm10,%xmm11
  40c604:	addps  %xmm15,%xmm2
  40c608:	shufps $0xaa,%xmm10,%xmm11
  40c60d:	shufps $0xff,%xmm10,%xmm10
  40c612:	addps  %xmm15,%xmm5
  40c616:	movaps %xmm4,0xc0(%rsp)
  40c61e:	mulps  %xmm11,%xmm12
  40c622:	movaps %xmm2,0xd0(%rsp)
  40c62a:	mulps  %xmm13,%xmm10
  40c62e:	movaps %xmm5,0xe0(%rsp)
  40c636:	addps  %xmm12,%xmm1
  40c63a:	movss  0xc4(%rsp),%xmm6
  40c643:	movss  0xc0(%rsp),%xmm12
  40c64d:	movss  0xc8(%rsp),%xmm0
  40c656:	addps  %xmm1,%xmm10
  40c65a:	movss  0xcc(%rsp),%xmm3
  40c663:	movss  0xd0(%rsp),%xmm7
  40c66c:	movss  0xd4(%rsp),%xmm13
  40c676:	movss  0xd8(%rsp),%xmm8
  40c680:	movss  %xmm12,0x23cc97(%rip)        # 649320 <invmatrix>
  40c689:	movaps %xmm10,0xf0(%rsp)
  40c692:	movss  %xmm6,0x23cc8a(%rip)        # 649324 <invmatrix+0x4>
  40c69a:	movss  %xmm0,0x23cc86(%rip)        # 649328 <invmatrix+0x8>
  40c6a2:	movss  %xmm3,0x23cc82(%rip)        # 64932c <invmatrix+0xc>
  40c6aa:	movss  %xmm7,0x23cc7e(%rip)        # 649330 <invmatrix+0x10>
  40c6b2:	movss  %xmm13,0x23cc79(%rip)        # 649334 <invmatrix+0x14>
  40c6bb:	movss  %xmm8,0x23cc74(%rip)        # 649338 <invmatrix+0x18>
  40c6c4:	movss  0xdc(%rsp),%xmm9
  40c6ce:	movss  0xe0(%rsp),%xmm15
  40c6d8:	movss  0xe4(%rsp),%xmm1
  40c6e1:	movss  0xe8(%rsp),%xmm14
  40c6eb:	movss  0xec(%rsp),%xmm11
  40c6f5:	movss  0xf0(%rsp),%xmm12
  40c6ff:	movss  0xf4(%rsp),%xmm6
  40c708:	movss  0xf8(%rsp),%xmm0
  40c711:	movss  0xfc(%rsp),%xmm3
  40c71a:	movss  %xmm9,0x23cc19(%rip)        # 64933c <invmatrix+0x1c>
  40c723:	movss  %xmm15,0x23cc14(%rip)        # 649340 <invmatrix+0x20>
  40c72c:	movss  %xmm1,0x23cc10(%rip)        # 649344 <invmatrix+0x24>
  40c734:	movss  %xmm14,0x23cc0b(%rip)        # 649348 <invmatrix+0x28>
  40c73d:	movss  %xmm11,0x23cc06(%rip)        # 64934c <invmatrix+0x2c>
  40c746:	movss  %xmm12,0x23cc01(%rip)        # 649350 <invmatrix+0x30>
  40c74f:	movss  %xmm6,0x23cbfd(%rip)        # 649354 <invmatrix+0x34>
  40c757:	movss  %xmm0,0x23cbf9(%rip)        # 649358 <invmatrix+0x38>
  40c75f:	movss  %xmm3,0x23cbf5(%rip)        # 64935c <invmatrix+0x3c>
  40c767:	movaps %xmm4,0x23cc32(%rip)        # 6493a0 <transformation_matrix>
  40c76e:	movaps %xmm2,0x23cc3b(%rip)        # 6493b0 <transformation_matrix+0x10>
  40c775:	movaps %xmm5,0x23cc44(%rip)        # 6493c0 <transformation_matrix+0x20>
  40c77c:	movaps %xmm10,0x23cc4c(%rip)        # 6493d0 <transformation_matrix+0x30>
  40c784:	callq  40b430 <Compute_Input_Dimensions>
  40c789:	add    $0x108,%rsp
  40c790:	jmpq   40b720 <Compute_Input_Unit_Vector>
  40c795:	nop
  40c796:	nopw   %cs:0x0(%rax,%rax,1)

000000000040c7a0 <Load_Transformation_Matrix>:
  40c7a0:	lea    0x10(%rdi),%rax
  40c7a4:	cmp    $0x6493a0,%rax
  40c7aa:	jbe    40c7b5 <Load_Transformation_Matrix+0x15>
  40c7ac:	cmp    $0x6493b0,%rdi
  40c7b3:	jb     40c7e8 <Load_Transformation_Matrix+0x48>
  40c7b5:	movups (%rdi),%xmm0
  40c7b8:	movups 0x10(%rdi),%xmm1
  40c7bc:	movups 0x20(%rdi),%xmm2
  40c7c0:	movups 0x30(%rdi),%xmm3
  40c7c4:	movaps %xmm0,0x23cbd5(%rip)        # 6493a0 <transformation_matrix>
  40c7cb:	movaps %xmm1,0x23cbde(%rip)        # 6493b0 <transformation_matrix+0x10>
  40c7d2:	movaps %xmm2,0x23cbe7(%rip)        # 6493c0 <transformation_matrix+0x20>
  40c7d9:	movaps %xmm3,0x23cbf0(%rip)        # 6493d0 <transformation_matrix+0x30>
  40c7e0:	retq   
  40c7e1:	nopl   0x0(%rax)
  40c7e8:	movss  (%rdi),%xmm0
  40c7ec:	movss  %xmm0,0x23cbac(%rip)        # 6493a0 <transformation_matrix>
  40c7f4:	movss  0x4(%rdi),%xmm1
  40c7f9:	movss  %xmm1,0x23cba3(%rip)        # 6493a4 <transformation_matrix+0x4>
  40c801:	movss  0x8(%rdi),%xmm2
  40c806:	movss  %xmm2,0x23cb9a(%rip)        # 6493a8 <transformation_matrix+0x8>
  40c80e:	movss  0xc(%rdi),%xmm3
  40c813:	movss  %xmm3,0x23cb91(%rip)        # 6493ac <transformation_matrix+0xc>
  40c81b:	movss  0x10(%rdi),%xmm4
  40c820:	movss  %xmm4,0x23cb88(%rip)        # 6493b0 <transformation_matrix+0x10>
  40c828:	movss  0x14(%rdi),%xmm5
  40c82d:	movss  %xmm5,0x23cb7f(%rip)        # 6493b4 <transformation_matrix+0x14>
  40c835:	movss  0x18(%rdi),%xmm6
  40c83a:	movss  %xmm6,0x23cb76(%rip)        # 6493b8 <transformation_matrix+0x18>
  40c842:	movss  0x1c(%rdi),%xmm7
  40c847:	movss  %xmm7,0x23cb6d(%rip)        # 6493bc <transformation_matrix+0x1c>
  40c84f:	movss  0x20(%rdi),%xmm8
  40c855:	movss  %xmm8,0x23cb62(%rip)        # 6493c0 <transformation_matrix+0x20>
  40c85e:	movss  0x24(%rdi),%xmm9
  40c864:	movss  %xmm9,0x23cb57(%rip)        # 6493c4 <transformation_matrix+0x24>
  40c86d:	movss  0x28(%rdi),%xmm10
  40c873:	movss  %xmm10,0x23cb4c(%rip)        # 6493c8 <transformation_matrix+0x28>
  40c87c:	movss  0x2c(%rdi),%xmm11
  40c882:	movss  %xmm11,0x23cb41(%rip)        # 6493cc <transformation_matrix+0x2c>
  40c88b:	movss  0x30(%rdi),%xmm12
  40c891:	movss  %xmm12,0x23cb36(%rip)        # 6493d0 <transformation_matrix+0x30>
  40c89a:	movss  0x34(%rdi),%xmm13
  40c8a0:	movss  %xmm13,0x23cb2b(%rip)        # 6493d4 <transformation_matrix+0x34>
  40c8a9:	movss  0x38(%rdi),%xmm14
  40c8af:	movss  %xmm14,0x23cb20(%rip)        # 6493d8 <transformation_matrix+0x38>
  40c8b8:	movss  0x3c(%rdi),%xmm15
  40c8be:	movss  %xmm15,0x23cb15(%rip)        # 6493dc <transformation_matrix+0x3c>
  40c8c7:	retq   
  40c8c8:	nopl   0x0(%rax,%rax,1)

000000000040c8d0 <Transform_Point>:
  40c8d0:	movss  0x23cac8(%rip),%xmm3        # 6493a0 <transformation_matrix>
  40c8d8:	cvtsd2ss %xmm0,%xmm0
  40c8dc:	cvtsd2ss %xmm1,%xmm1
  40c8e0:	movss  0x23cac8(%rip),%xmm4        # 6493b0 <transformation_matrix+0x10>
  40c8e8:	mulss  %xmm0,%xmm3
  40c8ec:	cvtsd2ss %xmm2,%xmm2
  40c8f0:	mulss  %xmm1,%xmm4
  40c8f4:	movss  0x23cac4(%rip),%xmm5        # 6493c0 <transformation_matrix+0x20>
  40c8fc:	mulss  %xmm2,%xmm5
  40c900:	addss  %xmm4,%xmm3
  40c904:	addss  %xmm5,%xmm3
  40c908:	addss  0x23cac0(%rip),%xmm3        # 6493d0 <transformation_matrix+0x30>
  40c910:	movss  %xmm3,(%rdi)
  40c914:	movss  0x23ca88(%rip),%xmm6        # 6493a4 <transformation_matrix+0x4>
  40c91c:	movss  0x23ca90(%rip),%xmm7        # 6493b4 <transformation_matrix+0x14>
  40c924:	mulss  %xmm0,%xmm6
  40c928:	mulss  %xmm1,%xmm7
  40c92c:	movss  0x23ca8f(%rip),%xmm8        # 6493c4 <transformation_matrix+0x24>
  40c935:	mulss  %xmm2,%xmm8
  40c93a:	addss  %xmm7,%xmm6
  40c93e:	addss  %xmm8,%xmm6
  40c943:	addss  0x23ca89(%rip),%xmm6        # 6493d4 <transformation_matrix+0x34>
  40c94b:	movss  %xmm6,(%rsi)
  40c94f:	mulss  0x23ca51(%rip),%xmm0        # 6493a8 <transformation_matrix+0x8>
  40c957:	mulss  0x23ca59(%rip),%xmm1        # 6493b8 <transformation_matrix+0x18>
  40c95f:	mulss  0x23ca61(%rip),%xmm2        # 6493c8 <transformation_matrix+0x28>
  40c967:	addss  %xmm1,%xmm0
  40c96b:	addss  %xmm2,%xmm0
  40c96f:	addss  0x23ca61(%rip),%xmm0        # 6493d8 <transformation_matrix+0x38>
  40c977:	movss  %xmm0,(%rdx)
  40c97b:	retq   
  40c97c:	nopl   0x0(%rax)

000000000040c980 <Inverse_Concatenate_Translation>:
  40c980:	pxor   %xmm4,%xmm4
  40c984:	movl   $0x3f800000,-0xc(%rsp)
  40c98c:	pxor   %xmm5,%xmm5
  40c990:	movss  0x14(%rdi),%xmm8
  40c996:	pxor   %xmm6,%xmm6
  40c99a:	cvtsd2ss %xmm0,%xmm4
  40c99e:	pxor   %xmm0,%xmm0
  40c9a2:	cvtsd2ss %xmm2,%xmm5
  40c9a6:	cvtsd2ss %xmm1,%xmm0
  40c9aa:	movss  0x4(%rdi),%xmm1
  40c9af:	movss  0xc(%rdi),%xmm2
  40c9b4:	movss  %xmm4,-0x18(%rsp)
  40c9ba:	movss  (%rdi),%xmm4
  40c9be:	unpcklps %xmm1,%xmm4
  40c9c1:	movss  0x10(%rdi),%xmm1
  40c9c6:	unpcklps %xmm8,%xmm1
  40c9ca:	movss  0x8(%rdi),%xmm7
  40c9cf:	movss  0x1c(%rdi),%xmm3
  40c9d4:	unpcklps %xmm2,%xmm7
  40c9d7:	movss  0x18(%rdi),%xmm2
  40c9dc:	unpcklps %xmm3,%xmm2
  40c9df:	movss  0x24(%rdi),%xmm13
  40c9e5:	movaps %xmm1,%xmm12
  40c9e9:	movss  %xmm0,-0x14(%rsp)
  40c9ef:	movss  0x20(%rdi),%xmm3
  40c9f4:	unpcklps %xmm13,%xmm3
  40c9f8:	movlhps %xmm2,%xmm12
  40c9fc:	movss  0x2c(%rdi),%xmm9
  40ca02:	movaps %xmm4,%xmm11
  40ca06:	movss  0x28(%rdi),%xmm2
  40ca0b:	movss  0x3c(%rdi),%xmm15
  40ca11:	movss  0x38(%rdi),%xmm1
  40ca16:	unpcklps %xmm9,%xmm2
  40ca1a:	movss  0x34(%rdi),%xmm0
  40ca1f:	movss  0x30(%rdi),%xmm4
  40ca24:	unpcklps %xmm15,%xmm1
  40ca28:	unpcklps %xmm0,%xmm4
  40ca2b:	movss  %xmm5,-0x10(%rsp)
  40ca31:	movaps %xmm3,%xmm14
  40ca35:	movlhps %xmm7,%xmm11
  40ca39:	movaps %xmm12,%xmm5
  40ca3d:	movlhps %xmm2,%xmm14
  40ca41:	movlhps %xmm1,%xmm4
  40ca44:	movaps -0x18(%rsp),%xmm10
  40ca4a:	movaps %xmm14,%xmm2
  40ca4e:	movaps %xmm4,%xmm9
  40ca52:	mulps  %xmm6,%xmm5
  40ca55:	movaps %xmm10,%xmm3
  40ca59:	mulps  %xmm6,%xmm9
  40ca5d:	mulps  %xmm6,%xmm2
  40ca60:	movaps %xmm5,%xmm8
  40ca64:	mulps  %xmm11,%xmm6
  40ca68:	addps  %xmm11,%xmm8
  40ca6c:	shufps $0x55,%xmm10,%xmm3
  40ca71:	movaps %xmm6,%xmm13
  40ca75:	mulps  %xmm12,%xmm3
  40ca79:	addps  %xmm6,%xmm5
  40ca7c:	addps  %xmm12,%xmm13
  40ca80:	movaps %xmm10,%xmm12
  40ca84:	addps  %xmm2,%xmm8
  40ca88:	shufps $0x0,%xmm10,%xmm12
  40ca8d:	addps  %xmm14,%xmm5
  40ca91:	mulps  %xmm12,%xmm11
  40ca95:	addps  %xmm2,%xmm13
  40ca99:	addps  %xmm9,%xmm8
  40ca9d:	addps  %xmm11,%xmm3
  40caa1:	movaps %xmm10,%xmm11
  40caa5:	addps  %xmm9,%xmm13
  40caa9:	shufps $0xaa,%xmm10,%xmm11
  40caae:	shufps $0xff,%xmm10,%xmm10
  40cab3:	addps  %xmm9,%xmm5
  40cab7:	movups %xmm8,(%rdi)
  40cabb:	mulps  %xmm11,%xmm14
  40cabf:	movups %xmm13,0x10(%rdi)
  40cac4:	mulps  %xmm4,%xmm10
  40cac8:	movups %xmm5,0x20(%rdi)
  40cacc:	addps  %xmm14,%xmm3
  40cad0:	addps  %xmm3,%xmm10
  40cad4:	movups %xmm10,0x30(%rdi)
  40cad9:	retq   
  40cada:	nopw   0x0(%rax,%rax,1)

000000000040cae0 <Inverse_Concatenate_Scaling>:
  40cae0:	pxor   %xmm6,%xmm6
  40cae4:	movq   $0x0,-0x3c(%rsp)
  40caed:	pxor   %xmm7,%xmm7
  40caf1:	movq   $0x0,-0x30(%rsp)
  40cafa:	movss  0x14(%rdi),%xmm8
  40cb00:	movq   $0x0,-0x44(%rsp)
  40cb09:	cvtsd2ss %xmm0,%xmm6
  40cb0d:	movq   $0x0,-0x1c(%rsp)
  40cb16:	movq   $0x0,-0x28(%rsp)
  40cb1f:	movq   $0x0,-0x14(%rsp)
  40cb28:	movl   $0x3f800000,-0xc(%rsp)
  40cb30:	pxor   %xmm0,%xmm0
  40cb34:	movss  0x24(%rdi),%xmm13
  40cb3a:	cvtsd2ss %xmm2,%xmm7
  40cb3e:	cvtsd2ss %xmm1,%xmm0
  40cb42:	movss  0x4(%rdi),%xmm1
  40cb47:	movss  0x20(%rdi),%xmm5
  40cb4c:	movss  %xmm6,-0x48(%rsp)
  40cb52:	unpcklps %xmm13,%xmm5
  40cb56:	movss  (%rdi),%xmm6
  40cb5a:	unpcklps %xmm1,%xmm6
  40cb5d:	movss  0x10(%rdi),%xmm1
  40cb62:	unpcklps %xmm8,%xmm1
  40cb66:	movss  0xc(%rdi),%xmm2
  40cb6b:	movaps %xmm5,%xmm14
  40cb6f:	movss  0x8(%rdi),%xmm4
  40cb74:	movss  %xmm7,-0x20(%rsp)
  40cb7a:	unpcklps %xmm2,%xmm4
  40cb7d:	movss  %xmm0,-0x34(%rsp)
  40cb83:	movaps %xmm6,%xmm10
  40cb87:	movss  0x1c(%rdi),%xmm3
  40cb8c:	movss  0x18(%rdi),%xmm2
  40cb91:	movaps %xmm1,%xmm11
  40cb95:	movaps -0x38(%rsp),%xmm7
  40cb9a:	unpcklps %xmm3,%xmm2
  40cb9d:	movlhps %xmm4,%xmm10
  40cba1:	movss  0x3c(%rdi),%xmm15
  40cba7:	movss  0x38(%rdi),%xmm1
  40cbac:	movaps %xmm7,%xmm5
  40cbaf:	unpcklps %xmm15,%xmm1
  40cbb3:	movaps %xmm7,%xmm15
  40cbb7:	movss  0x34(%rdi),%xmm0
  40cbbc:	movss  0x30(%rdi),%xmm4
  40cbc1:	unpcklps %xmm0,%xmm4
  40cbc4:	movlhps %xmm2,%xmm11
  40cbc8:	shufps $0x55,%xmm7,%xmm5
  40cbcc:	shufps $0x0,%xmm7,%xmm15
  40cbd1:	movss  0x2c(%rdi),%xmm9
  40cbd7:	movss  0x28(%rdi),%xmm2
  40cbdc:	movlhps %xmm1,%xmm4
  40cbdf:	unpcklps %xmm9,%xmm2
  40cbe3:	mulps  %xmm11,%xmm5
  40cbe7:	movaps %xmm7,%xmm1
  40cbea:	movaps -0x48(%rsp),%xmm3
  40cbef:	mulps  %xmm10,%xmm15
  40cbf3:	movlhps %xmm2,%xmm14
  40cbf7:	movaps -0x28(%rsp),%xmm12
  40cbfd:	shufps $0xaa,%xmm7,%xmm1
  40cc01:	shufps $0xff,%xmm7,%xmm7
  40cc05:	movaps %xmm3,%xmm8
  40cc09:	movaps %xmm3,%xmm9
  40cc0d:	mulps  %xmm14,%xmm1
  40cc11:	addps  %xmm15,%xmm5
  40cc15:	movaps -0x18(%rsp),%xmm13
  40cc1b:	mulps  %xmm4,%xmm7
  40cc1e:	movaps %xmm3,%xmm2
  40cc21:	movaps %xmm12,%xmm6
  40cc25:	shufps $0x0,%xmm3,%xmm8
  40cc2a:	movaps %xmm12,%xmm0
  40cc2e:	addps  %xmm1,%xmm5
  40cc31:	shufps $0x55,%xmm3,%xmm9
  40cc36:	mulps  %xmm10,%xmm8
  40cc3a:	mulps  %xmm11,%xmm9
  40cc3e:	addps  %xmm5,%xmm7
  40cc41:	shufps $0xaa,%xmm3,%xmm2
  40cc45:	shufps $0x55,%xmm12,%xmm6
  40cc4a:	shufps $0xff,%xmm3,%xmm3
  40cc4e:	mulps  %xmm14,%xmm2
  40cc52:	addps  %xmm9,%xmm8
  40cc56:	movups %xmm7,0x10(%rdi)
  40cc5a:	movaps %xmm13,%xmm7
  40cc5e:	mulps  %xmm11,%xmm6
  40cc62:	shufps $0x55,%xmm13,%xmm7
  40cc67:	addps  %xmm2,%xmm8
  40cc6b:	mulps  %xmm4,%xmm3
  40cc6e:	mulps  %xmm11,%xmm7
  40cc72:	movaps %xmm13,%xmm11
  40cc76:	shufps $0x0,%xmm12,%xmm0
  40cc7b:	shufps $0x0,%xmm13,%xmm11
  40cc80:	addps  %xmm8,%xmm3
  40cc84:	mulps  %xmm10,%xmm0
  40cc88:	mulps  %xmm11,%xmm10
  40cc8c:	movups %xmm3,(%rdi)
  40cc8f:	movaps %xmm12,%xmm3
  40cc93:	addps  %xmm0,%xmm6
  40cc96:	shufps $0xaa,%xmm12,%xmm3
  40cc9b:	addps  %xmm10,%xmm7
  40cc9f:	movaps %xmm13,%xmm10
  40cca3:	shufps $0xff,%xmm12,%xmm12
  40cca8:	shufps $0xaa,%xmm13,%xmm10
  40ccad:	mulps  %xmm14,%xmm3
  40ccb1:	mulps  %xmm10,%xmm14
  40ccb5:	shufps $0xff,%xmm13,%xmm13
  40ccba:	addps  %xmm3,%xmm6
  40ccbd:	mulps  %xmm4,%xmm12
  40ccc1:	addps  %xmm14,%xmm7
  40ccc5:	mulps  %xmm4,%xmm13
  40ccc9:	addps  %xmm6,%xmm12
  40cccd:	addps  %xmm7,%xmm13
  40ccd1:	movups %xmm12,0x20(%rdi)
  40ccd6:	movups %xmm13,0x30(%rdi)
  40ccdb:	retq   
  40ccdc:	nopl   0x0(%rax)

000000000040cce0 <Inverse_Concatenate_Rotation>:
  40cce0:	push   %rbx
  40cce1:	cvtsd2ss %xmm0,%xmm0
  40cce5:	mov    %rdi,%rbx
  40cce8:	cvtss2sd %xmm0,%xmm0
  40ccec:	sub    $0x50,%rsp
  40ccf0:	cmp    $0x1,%rsi
  40ccf4:	movss  0xcc74(%rip),%xmm1        # 419970 <__dso_handle+0xba8>
  40ccfc:	movaps 0xccad(%rip),%xmm2        # 4199b0 <__dso_handle+0xbe8>
  40cd03:	movaps 0xcc56(%rip),%xmm3        # 419960 <__dso_handle+0xb98>
  40cd0a:	movaps 0xcc0f(%rip),%xmm4        # 419920 <__dso_handle+0xb58>
  40cd11:	movaps %xmm1,0x10(%rsp)
  40cd16:	movaps %xmm2,0x20(%rsp)
  40cd1b:	movaps %xmm3,0x30(%rsp)
  40cd20:	movaps %xmm4,0x40(%rsp)
  40cd25:	je     40cf68 <Inverse_Concatenate_Rotation+0x288>
  40cd2b:	cmp    $0x2,%rsi
  40cd2f:	je     40cd90 <Inverse_Concatenate_Rotation+0xb0>
  40cd31:	cmp    $0x3,%rsi
  40cd35:	jne    40cde8 <Inverse_Concatenate_Rotation+0x108>
  40cd3b:	divsd  0xcbcd(%rip),%xmm0        # 419910 <__dso_handle+0xb48>
  40cd43:	lea    0x8(%rsp),%rdi
  40cd48:	mov    %rsp,%rsi
  40cd4b:	mulsd  0xcbc5(%rip),%xmm0        # 419918 <__dso_handle+0xb50>
  40cd53:	callq  4011e0 <sincos@plt>
  40cd58:	pxor   %xmm6,%xmm6
  40cd5c:	pxor   %xmm5,%xmm5
  40cd60:	cvtsd2ss 0x8(%rsp),%xmm6
  40cd66:	movss  %xmm6,0x14(%rsp)
  40cd6c:	xorps  0xc08d(%rip),%xmm6        # 418e00 <__dso_handle+0x38>
  40cd73:	cvtsd2ss (%rsp),%xmm5
  40cd78:	movss  %xmm5,0x10(%rsp)
  40cd7e:	movss  %xmm5,0x24(%rsp)
  40cd84:	movss  %xmm6,0x20(%rsp)
  40cd8a:	jmp    40cde8 <Inverse_Concatenate_Rotation+0x108>
  40cd8c:	nopl   0x0(%rax)
  40cd90:	divsd  0xcb78(%rip),%xmm0        # 419910 <__dso_handle+0xb48>
  40cd98:	lea    0x8(%rsp),%rdi
  40cd9d:	mov    %rsp,%rsi
  40cda0:	mulsd  0xcb70(%rip),%xmm0        # 419918 <__dso_handle+0xb50>
  40cda8:	callq  4011e0 <sincos@plt>
  40cdad:	pxor   %xmm8,%xmm8
  40cdb2:	pxor   %xmm7,%xmm7
  40cdb6:	cvtsd2ss 0x8(%rsp),%xmm8
  40cdbd:	movaps %xmm8,%xmm9
  40cdc1:	movss  %xmm8,0x30(%rsp)
  40cdc8:	cvtsd2ss (%rsp),%xmm7
  40cdcd:	movss  %xmm7,0x10(%rsp)
  40cdd3:	movss  %xmm7,0x38(%rsp)
  40cdd9:	xorps  0xc01f(%rip),%xmm9        # 418e00 <__dso_handle+0x38>
  40cde1:	movss  %xmm9,0x18(%rsp)
  40cde8:	movss  0x4(%rbx),%xmm14
  40cdee:	movss  (%rbx),%xmm5
  40cdf2:	unpcklps %xmm14,%xmm5
  40cdf6:	movss  0xc(%rbx),%xmm12
  40cdfc:	movss  0x8(%rbx),%xmm1
  40ce01:	unpcklps %xmm12,%xmm1
  40ce05:	movss  0x1c(%rbx),%xmm0
  40ce0a:	movaps %xmm5,%xmm15
  40ce0e:	movss  0x14(%rbx),%xmm3
  40ce13:	movlhps %xmm1,%xmm15
  40ce17:	movss  0x18(%rbx),%xmm1
  40ce1c:	unpcklps %xmm0,%xmm1
  40ce1f:	movss  0x10(%rbx),%xmm0
  40ce24:	unpcklps %xmm3,%xmm0
  40ce27:	movaps 0x10(%rsp),%xmm14
  40ce2d:	movss  0x2c(%rbx),%xmm4
  40ce32:	movaps %xmm0,%xmm9
  40ce36:	movss  0x24(%rbx),%xmm8
  40ce3c:	movaps %xmm14,%xmm2
  40ce40:	movlhps %xmm1,%xmm9
  40ce44:	movss  0x28(%rbx),%xmm1
  40ce49:	unpcklps %xmm4,%xmm1
  40ce4c:	movaps %xmm14,%xmm3
  40ce50:	movss  0x20(%rbx),%xmm4
  40ce55:	unpcklps %xmm8,%xmm4
  40ce59:	shufps $0x0,%xmm14,%xmm2
  40ce5e:	movaps %xmm14,%xmm7
  40ce62:	shufps $0x55,%xmm14,%xmm3
  40ce67:	movaps %xmm4,%xmm10
  40ce6b:	movss  0x3c(%rbx),%xmm6
  40ce70:	mulps  %xmm15,%xmm2
  40ce74:	movlhps %xmm1,%xmm10
  40ce78:	movss  0x38(%rbx),%xmm1
  40ce7d:	mulps  %xmm9,%xmm3
  40ce81:	movss  0x34(%rbx),%xmm12
  40ce87:	unpcklps %xmm6,%xmm1
  40ce8a:	movss  0x30(%rbx),%xmm6
  40ce8f:	shufps $0xaa,%xmm14,%xmm7
  40ce94:	unpcklps %xmm12,%xmm6
  40ce98:	movaps 0x20(%rsp),%xmm5
  40ce9d:	addps  %xmm3,%xmm2
  40cea0:	mulps  %xmm10,%xmm7
  40cea4:	movaps 0x30(%rsp),%xmm0
  40cea9:	movaps %xmm6,%xmm13
  40cead:	shufps $0xff,%xmm14,%xmm14
  40ceb2:	movaps %xmm5,%xmm8
  40ceb6:	movlhps %xmm1,%xmm13
  40ceba:	movaps %xmm5,%xmm4
  40cebd:	movaps %xmm0,%xmm11
  40cec1:	addps  %xmm7,%xmm2
  40cec4:	mulps  %xmm13,%xmm14
  40cec8:	movaps %xmm0,%xmm12
  40cecc:	shufps $0x55,%xmm5,%xmm8
  40ced1:	movaps %xmm5,%xmm1
  40ced4:	shufps $0x0,%xmm5,%xmm4
  40ced8:	shufps $0x55,%xmm0,%xmm11
  40cedd:	movaps %xmm0,%xmm6
  40cee0:	addps  %xmm2,%xmm14
  40cee4:	shufps $0x0,%xmm0,%xmm12
  40cee9:	mulps  %xmm9,%xmm8
  40ceed:	mulps  %xmm15,%xmm4
  40cef1:	movups %xmm14,(%rbx)
  40cef5:	pxor   %xmm14,%xmm14
  40cefa:	mulps  %xmm9,%xmm11
  40cefe:	mulps  %xmm15,%xmm12
  40cf02:	addps  %xmm4,%xmm8
  40cf06:	mulps  %xmm14,%xmm9
  40cf0a:	mulps  %xmm14,%xmm15
  40cf0e:	addps  %xmm12,%xmm11
  40cf12:	shufps $0xaa,%xmm5,%xmm1
  40cf16:	shufps $0xaa,%xmm0,%xmm6
  40cf1a:	shufps $0xff,%xmm5,%xmm5
  40cf1e:	mulps  %xmm10,%xmm1
  40cf22:	addps  %xmm15,%xmm9
  40cf26:	mulps  %xmm10,%xmm6
  40cf2a:	mulps  %xmm14,%xmm10
  40cf2e:	addps  %xmm1,%xmm8
  40cf32:	shufps $0xff,%xmm0,%xmm0
  40cf36:	mulps  %xmm13,%xmm5
  40cf3a:	addps  %xmm6,%xmm11
  40cf3e:	mulps  %xmm13,%xmm0
  40cf42:	addps  %xmm10,%xmm9
  40cf46:	addps  %xmm8,%xmm5
  40cf4a:	addps  %xmm11,%xmm0
  40cf4e:	addps  %xmm13,%xmm9
  40cf52:	movups %xmm5,0x10(%rbx)
  40cf56:	movups %xmm0,0x20(%rbx)
  40cf5a:	movups %xmm9,0x30(%rbx)
  40cf5f:	add    $0x50,%rsp
  40cf63:	pop    %rbx
  40cf64:	retq   
  40cf65:	nopl   (%rax)
  40cf68:	divsd  0xc9a0(%rip),%xmm0        # 419910 <__dso_handle+0xb48>
  40cf70:	lea    0x8(%rsp),%rdi
  40cf75:	mov    %rsp,%rsi
  40cf78:	mulsd  0xc998(%rip),%xmm0        # 419918 <__dso_handle+0xb50>
  40cf80:	callq  4011e0 <sincos@plt>
  40cf85:	pxor   %xmm11,%xmm11
  40cf8a:	pxor   %xmm10,%xmm10
  40cf8f:	cvtsd2ss 0x8(%rsp),%xmm11
  40cf96:	movss  %xmm11,0x28(%rsp)
  40cf9d:	xorps  0xbe5b(%rip),%xmm11        # 418e00 <__dso_handle+0x38>
  40cfa5:	cvtsd2ss (%rsp),%xmm10
  40cfab:	movss  %xmm10,0x24(%rsp)
  40cfb2:	movss  %xmm10,0x38(%rsp)
  40cfb9:	movss  %xmm11,0x34(%rsp)
  40cfc0:	jmpq   40cde8 <Inverse_Concatenate_Rotation+0x108>
  40cfc5:	nop
  40cfc6:	nopw   %cs:0x0(%rax,%rax,1)

000000000040cfd0 <Load_Identity_Matrix>:
  40cfd0:	movabs $0x3f80000000000000,%rax
  40cfda:	movq   $0x3f800000,(%rdi)
  40cfe1:	movq   $0x0,0x8(%rdi)
  40cfe9:	mov    %rax,0x10(%rdi)
  40cfed:	movq   $0x0,0x18(%rdi)
  40cff5:	movq   $0x0,0x20(%rdi)
  40cffd:	movq   $0x3f800000,0x28(%rdi)
  40d005:	movq   $0x0,0x30(%rdi)
  40d00d:	mov    %rax,0x38(%rdi)
  40d011:	retq   
  40d012:	nopl   0x0(%rax)
  40d016:	nopw   %cs:0x0(%rax,%rax,1)

000000000040d020 <Load_Translation_Matrix>:
  40d020:	pxor   %xmm3,%xmm3
  40d024:	movabs $0x3f80000000000000,%rax
  40d02e:	pxor   %xmm4,%xmm4
  40d032:	mov    %rax,0x38(%rdi)
  40d036:	pxor   %xmm5,%xmm5
  40d03a:	movq   $0x3f800000,(%rdi)
  40d041:	cvtsd2ss %xmm0,%xmm3
  40d045:	movq   $0x0,0x8(%rdi)
  40d04d:	mov    %rax,0x10(%rdi)
  40d051:	movq   $0x0,0x18(%rdi)
  40d059:	movq   $0x0,0x20(%rdi)
  40d061:	cvtsd2ss %xmm1,%xmm4
  40d065:	movq   $0x3f800000,0x28(%rdi)
  40d06d:	cvtsd2ss %xmm2,%xmm5
  40d071:	movss  %xmm3,0x30(%rdi)
  40d076:	movss  %xmm4,0x34(%rdi)
  40d07b:	movss  %xmm5,0x38(%rdi)
  40d080:	retq   
  40d081:	nopl   0x0(%rax,%rax,1)
  40d086:	nopw   %cs:0x0(%rax,%rax,1)

000000000040d090 <Load_Scaling_Matrix>:
  40d090:	pxor   %xmm3,%xmm3
  40d094:	movabs $0x3f80000000000000,%rax
  40d09e:	pxor   %xmm4,%xmm4
  40d0a2:	movq   $0x3f800000,0x14(%rdi)
  40d0aa:	pxor   %xmm5,%xmm5
  40d0ae:	mov    %rax,0x24(%rdi)
  40d0b2:	cvtsd2ss %xmm0,%xmm3
  40d0b6:	movq   $0x0,0x4(%rdi)
  40d0be:	movq   $0x0,0xc(%rdi)
  40d0c6:	movq   $0x0,0x1c(%rdi)
  40d0ce:	movq   $0x0,0x2c(%rdi)
  40d0d6:	cvtsd2ss %xmm1,%xmm4
  40d0da:	movq   $0x0,0x34(%rdi)
  40d0e2:	movl   $0x3f800000,0x3c(%rdi)
  40d0e9:	cvtsd2ss %xmm2,%xmm5
  40d0ed:	movss  %xmm3,(%rdi)
  40d0f1:	movss  %xmm4,0x14(%rdi)
  40d0f6:	movss  %xmm5,0x28(%rdi)
  40d0fb:	retq   
  40d0fc:	nopl   0x0(%rax)

000000000040d100 <Load_Rotation_Matrix>:
  40d100:	push   %rbx
  40d101:	movabs $0x3f80000000000000,%rax
  40d10b:	cvtsd2ss %xmm0,%xmm0
  40d10f:	mov    %rdi,%rbx
  40d112:	cvtss2sd %xmm0,%xmm0
  40d116:	sub    $0x10,%rsp
  40d11a:	cmp    $0x1,%rsi
  40d11e:	movq   $0x3f800000,(%rdi)
  40d125:	movq   $0x0,0x8(%rdi)
  40d12d:	mov    %rax,0x10(%rdi)
  40d131:	movq   $0x0,0x18(%rdi)
  40d139:	movq   $0x0,0x20(%rdi)
  40d141:	movq   $0x3f800000,0x28(%rdi)
  40d149:	movq   $0x0,0x30(%rdi)
  40d151:	mov    %rax,0x38(%rdi)
  40d155:	je     40d218 <Load_Rotation_Matrix+0x118>
  40d15b:	cmp    $0x2,%rsi
  40d15f:	je     40d1c0 <Load_Rotation_Matrix+0xc0>
  40d161:	cmp    $0x3,%rsi
  40d165:	jne    40d20d <Load_Rotation_Matrix+0x10d>
  40d16b:	divsd  0xc79d(%rip),%xmm0        # 419910 <__dso_handle+0xb48>
  40d173:	lea    0x8(%rsp),%rdi
  40d178:	mov    %rsp,%rsi
  40d17b:	mulsd  0xc795(%rip),%xmm0        # 419918 <__dso_handle+0xb50>
  40d183:	callq  4011e0 <sincos@plt>
  40d188:	pxor   %xmm2,%xmm2
  40d18c:	pxor   %xmm1,%xmm1
  40d190:	cvtsd2ss 0x8(%rsp),%xmm2
  40d196:	movss  %xmm2,0x4(%rbx)
  40d19b:	xorps  0xbc5e(%rip),%xmm2        # 418e00 <__dso_handle+0x38>
  40d1a2:	cvtsd2ss (%rsp),%xmm1
  40d1a7:	movss  %xmm1,(%rbx)
  40d1ab:	movss  %xmm1,0x14(%rbx)
  40d1b0:	movss  %xmm2,0x10(%rbx)
  40d1b5:	add    $0x10,%rsp
  40d1b9:	pop    %rbx
  40d1ba:	retq   
  40d1bb:	nopl   0x0(%rax,%rax,1)
  40d1c0:	divsd  0xc748(%rip),%xmm0        # 419910 <__dso_handle+0xb48>
  40d1c8:	lea    0x8(%rsp),%rdi
  40d1cd:	mov    %rsp,%rsi
  40d1d0:	mulsd  0xc740(%rip),%xmm0        # 419918 <__dso_handle+0xb50>
  40d1d8:	callq  4011e0 <sincos@plt>
  40d1dd:	pxor   %xmm4,%xmm4
  40d1e1:	pxor   %xmm3,%xmm3
  40d1e5:	cvtsd2ss 0x8(%rsp),%xmm4
  40d1eb:	movaps %xmm4,%xmm5
  40d1ee:	movss  %xmm4,0x20(%rbx)
  40d1f3:	cvtsd2ss (%rsp),%xmm3
  40d1f8:	movss  %xmm3,(%rbx)
  40d1fc:	movss  %xmm3,0x28(%rbx)
  40d201:	xorps  0xbbf8(%rip),%xmm5        # 418e00 <__dso_handle+0x38>
  40d208:	movss  %xmm5,0x8(%rbx)
  40d20d:	add    $0x10,%rsp
  40d211:	pop    %rbx
  40d212:	retq   
  40d213:	nopl   0x0(%rax,%rax,1)
  40d218:	divsd  0xc6f0(%rip),%xmm0        # 419910 <__dso_handle+0xb48>
  40d220:	lea    0x8(%rsp),%rdi
  40d225:	mov    %rsp,%rsi
  40d228:	mulsd  0xc6e8(%rip),%xmm0        # 419918 <__dso_handle+0xb50>
  40d230:	callq  4011e0 <sincos@plt>
  40d235:	pxor   %xmm7,%xmm7
  40d239:	pxor   %xmm6,%xmm6
  40d23d:	cvtsd2ss 0x8(%rsp),%xmm7
  40d243:	movss  %xmm7,0x18(%rbx)
  40d248:	xorps  0xbbb1(%rip),%xmm7        # 418e00 <__dso_handle+0x38>
  40d24f:	cvtsd2ss (%rsp),%xmm6
  40d254:	movss  %xmm6,0x14(%rbx)
  40d259:	movss  %xmm6,0x28(%rbx)
  40d25e:	movss  %xmm7,0x24(%rbx)
  40d263:	add    $0x10,%rsp
  40d267:	pop    %rbx
  40d268:	retq   
  40d269:	nopl   0x0(%rax)

000000000040d270 <Concatenate_Transform>:
  40d270:	movss  0x14(%rsi),%xmm1
  40d275:	movss  0x10(%rsi),%xmm5
  40d27a:	unpcklps %xmm1,%xmm5
  40d27d:	movss  0x4(%rsi),%xmm6
  40d282:	movss  (%rsi),%xmm7
  40d286:	unpcklps %xmm6,%xmm7
  40d289:	movss  0x24(%rsi),%xmm12
  40d28f:	movaps %xmm5,%xmm11
  40d293:	movss  0x20(%rsi),%xmm5
  40d298:	movss  0xc(%rsi),%xmm2
  40d29d:	unpcklps %xmm12,%xmm5
  40d2a1:	movss  0x8(%rsi),%xmm4
  40d2a6:	unpcklps %xmm2,%xmm4
  40d2a9:	movaps %xmm7,%xmm10
  40d2ad:	movups 0x10(%rdi),%xmm7
  40d2b1:	movaps %xmm5,%xmm13
  40d2b5:	movss  0x1c(%rsi),%xmm0
  40d2ba:	movaps %xmm7,%xmm5
  40d2bd:	movss  0x3c(%rsi),%xmm14
  40d2c3:	movss  0x18(%rsi),%xmm2
  40d2c8:	movlhps %xmm4,%xmm10
  40d2cc:	movss  0x38(%rsi),%xmm1
  40d2d1:	unpcklps %xmm0,%xmm2
  40d2d4:	movss  0x34(%rsi),%xmm6
  40d2d9:	unpcklps %xmm14,%xmm1
  40d2dd:	movaps %xmm7,%xmm14
  40d2e1:	movss  0x30(%rsi),%xmm4
  40d2e6:	unpcklps %xmm6,%xmm4
  40d2e9:	shufps $0x55,%xmm7,%xmm5
  40d2ed:	movlhps %xmm2,%xmm11
  40d2f1:	shufps $0x0,%xmm7,%xmm14
  40d2f6:	movss  0x2c(%rsi),%xmm8
  40d2fc:	movlhps %xmm1,%xmm4
  40d2ff:	movss  0x28(%rsi),%xmm2
  40d304:	unpcklps %xmm8,%xmm2
  40d308:	movaps %xmm7,%xmm1
  40d30b:	mulps  %xmm11,%xmm5
  40d30f:	movups (%rdi),%xmm3
  40d312:	mulps  %xmm10,%xmm14
  40d316:	movlhps %xmm2,%xmm13
  40d31a:	movaps %xmm3,%xmm8
  40d31e:	shufps $0xaa,%xmm7,%xmm1
  40d322:	movaps %xmm3,%xmm2
  40d325:	shufps $0xff,%xmm7,%xmm7
  40d329:	shufps $0x0,%xmm3,%xmm8
  40d32e:	movaps %xmm3,%xmm9
  40d332:	mulps  %xmm13,%xmm1
  40d336:	addps  %xmm14,%xmm5
  40d33a:	movups 0x20(%rdi),%xmm12
  40d33f:	mulps  %xmm4,%xmm7
  40d342:	movups 0x30(%rdi),%xmm0
  40d346:	movaps %xmm12,%xmm15
  40d34a:	shufps $0x55,%xmm3,%xmm2
  40d34e:	mulps  %xmm10,%xmm8
  40d352:	movaps %xmm12,%xmm6
  40d356:	addps  %xmm1,%xmm5
  40d359:	mulps  %xmm11,%xmm2
  40d35d:	shufps $0xaa,%xmm3,%xmm9
  40d362:	shufps $0x55,%xmm12,%xmm15
  40d367:	addps  %xmm5,%xmm7
  40d36a:	shufps $0xff,%xmm3,%xmm3
  40d36e:	mulps  %xmm13,%xmm9
  40d372:	addps  %xmm2,%xmm8
  40d376:	mulps  %xmm11,%xmm15
  40d37a:	movups %xmm7,0x10(%rdi)
  40d37e:	movaps %xmm0,%xmm7
  40d381:	addps  %xmm9,%xmm8
  40d385:	mulps  %xmm4,%xmm3
  40d388:	shufps $0x55,%xmm0,%xmm7
  40d38c:	shufps $0x0,%xmm12,%xmm6
  40d391:	mulps  %xmm11,%xmm7
  40d395:	movaps %xmm0,%xmm11
  40d399:	addps  %xmm8,%xmm3
  40d39d:	mulps  %xmm10,%xmm6
  40d3a1:	shufps $0x0,%xmm0,%xmm11
  40d3a6:	mulps  %xmm11,%xmm10
  40d3aa:	movups %xmm3,(%rdi)
  40d3ad:	movaps %xmm12,%xmm3
  40d3b1:	addps  %xmm6,%xmm15
  40d3b5:	shufps $0xaa,%xmm12,%xmm3
  40d3ba:	addps  %xmm10,%xmm7
  40d3be:	movaps %xmm0,%xmm10
  40d3c2:	shufps $0xff,%xmm12,%xmm12
  40d3c7:	shufps $0xaa,%xmm0,%xmm10
  40d3cc:	mulps  %xmm13,%xmm3
  40d3d0:	mulps  %xmm10,%xmm13
  40d3d4:	shufps $0xff,%xmm0,%xmm0
  40d3d8:	addps  %xmm3,%xmm15
  40d3dc:	mulps  %xmm4,%xmm12
  40d3e0:	addps  %xmm13,%xmm7
  40d3e4:	mulps  %xmm4,%xmm0
  40d3e7:	addps  %xmm15,%xmm12
  40d3eb:	addps  %xmm7,%xmm0
  40d3ee:	movups %xmm12,0x20(%rdi)
  40d3f3:	movups %xmm0,0x30(%rdi)
  40d3f7:	retq   
  40d3f8:	nopl   0x0(%rax,%rax,1)

000000000040d400 <Inverse_Concatenate_Transform>:
  40d400:	movss  0x14(%rdi),%xmm1
  40d405:	movss  0x10(%rdi),%xmm5
  40d40a:	unpcklps %xmm1,%xmm5
  40d40d:	movss  0x4(%rdi),%xmm6
  40d412:	movss  (%rdi),%xmm7
  40d416:	unpcklps %xmm6,%xmm7
  40d419:	movss  0x24(%rdi),%xmm12
  40d41f:	movaps %xmm5,%xmm11
  40d423:	movss  0x20(%rdi),%xmm5
  40d428:	movss  0xc(%rdi),%xmm2
  40d42d:	unpcklps %xmm12,%xmm5
  40d431:	movss  0x8(%rdi),%xmm4
  40d436:	unpcklps %xmm2,%xmm4
  40d439:	movaps %xmm7,%xmm10
  40d43d:	movups 0x10(%rsi),%xmm7
  40d441:	movaps %xmm5,%xmm13
  40d445:	movss  0x1c(%rdi),%xmm0
  40d44a:	movaps %xmm7,%xmm5
  40d44d:	movss  0x3c(%rdi),%xmm14
  40d453:	movss  0x18(%rdi),%xmm2
  40d458:	movlhps %xmm4,%xmm10
  40d45c:	movss  0x38(%rdi),%xmm1
  40d461:	unpcklps %xmm0,%xmm2
  40d464:	movss  0x34(%rdi),%xmm6
  40d469:	unpcklps %xmm14,%xmm1
  40d46d:	movaps %xmm7,%xmm14
  40d471:	movss  0x30(%rdi),%xmm4
  40d476:	unpcklps %xmm6,%xmm4
  40d479:	shufps $0x55,%xmm7,%xmm5
  40d47d:	movlhps %xmm2,%xmm11
  40d481:	shufps $0x0,%xmm7,%xmm14
  40d486:	movss  0x2c(%rdi),%xmm8
  40d48c:	movlhps %xmm1,%xmm4
  40d48f:	movss  0x28(%rdi),%xmm2
  40d494:	unpcklps %xmm8,%xmm2
  40d498:	movaps %xmm7,%xmm1
  40d49b:	mulps  %xmm11,%xmm5
  40d49f:	movups (%rsi),%xmm3
  40d4a2:	mulps  %xmm10,%xmm14
  40d4a6:	movlhps %xmm2,%xmm13
  40d4aa:	movaps %xmm3,%xmm8
  40d4ae:	shufps $0xaa,%xmm7,%xmm1
  40d4b2:	movaps %xmm3,%xmm2
  40d4b5:	shufps $0xff,%xmm7,%xmm7
  40d4b9:	shufps $0x0,%xmm3,%xmm8
  40d4be:	movaps %xmm3,%xmm9
  40d4c2:	mulps  %xmm13,%xmm1
  40d4c6:	addps  %xmm14,%xmm5
  40d4ca:	movups 0x20(%rsi),%xmm12
  40d4cf:	mulps  %xmm4,%xmm7
  40d4d2:	movups 0x30(%rsi),%xmm0
  40d4d6:	movaps %xmm12,%xmm15
  40d4da:	shufps $0x55,%xmm3,%xmm2
  40d4de:	mulps  %xmm10,%xmm8
  40d4e2:	movaps %xmm12,%xmm6
  40d4e6:	addps  %xmm1,%xmm5
  40d4e9:	mulps  %xmm11,%xmm2
  40d4ed:	shufps $0xaa,%xmm3,%xmm9
  40d4f2:	shufps $0x55,%xmm12,%xmm15
  40d4f7:	addps  %xmm5,%xmm7
  40d4fa:	shufps $0xff,%xmm3,%xmm3
  40d4fe:	mulps  %xmm13,%xmm9
  40d502:	addps  %xmm2,%xmm8
  40d506:	mulps  %xmm11,%xmm15
  40d50a:	movups %xmm7,0x10(%rdi)
  40d50e:	movaps %xmm0,%xmm7
  40d511:	addps  %xmm9,%xmm8
  40d515:	mulps  %xmm4,%xmm3
  40d518:	shufps $0x55,%xmm0,%xmm7
  40d51c:	shufps $0x0,%xmm12,%xmm6
  40d521:	mulps  %xmm11,%xmm7
  40d525:	movaps %xmm0,%xmm11
  40d529:	addps  %xmm8,%xmm3
  40d52d:	mulps  %xmm10,%xmm6
  40d531:	shufps $0x0,%xmm0,%xmm11
  40d536:	mulps  %xmm11,%xmm10
  40d53a:	movups %xmm3,(%rdi)
  40d53d:	movaps %xmm12,%xmm3
  40d541:	addps  %xmm6,%xmm15
  40d545:	shufps $0xaa,%xmm12,%xmm3
  40d54a:	addps  %xmm10,%xmm7
  40d54e:	movaps %xmm0,%xmm10
  40d552:	shufps $0xff,%xmm12,%xmm12
  40d557:	shufps $0xaa,%xmm0,%xmm10
  40d55c:	mulps  %xmm13,%xmm3
  40d560:	mulps  %xmm10,%xmm13
  40d564:	shufps $0xff,%xmm0,%xmm0
  40d568:	addps  %xmm3,%xmm15
  40d56c:	mulps  %xmm4,%xmm12
  40d570:	addps  %xmm13,%xmm7
  40d574:	mulps  %xmm4,%xmm0
  40d577:	addps  %xmm15,%xmm12
  40d57b:	addps  %xmm7,%xmm0
  40d57e:	movups %xmm12,0x20(%rdi)
  40d583:	movups %xmm0,0x30(%rdi)
  40d587:	retq   
  40d588:	nopl   0x0(%rax,%rax,1)

000000000040d590 <Multiply_Matrices>:
  40d590:	movss  0x10(%rsi),%xmm0
  40d595:	movss  (%rsi),%xmm1
  40d599:	mulss  0x4(%rdi),%xmm0
  40d59e:	mulss  (%rdi),%xmm1
  40d5a2:	movss  0x20(%rsi),%xmm2
  40d5a7:	mulss  0x8(%rdi),%xmm2
  40d5ac:	movss  0x30(%rsi),%xmm3
  40d5b1:	mulss  0xc(%rdi),%xmm3
  40d5b6:	addss  %xmm1,%xmm0
  40d5ba:	addss  %xmm2,%xmm0
  40d5be:	addss  %xmm3,%xmm0
  40d5c2:	movss  %xmm0,(%rdx)
  40d5c6:	movss  0x14(%rsi),%xmm4
  40d5cb:	movss  0x4(%rsi),%xmm5
  40d5d0:	mulss  0x4(%rdi),%xmm4
  40d5d5:	mulss  (%rdi),%xmm5
  40d5d9:	movss  0x8(%rdi),%xmm6
  40d5de:	mulss  0x24(%rsi),%xmm6
  40d5e3:	movss  0x34(%rsi),%xmm7
  40d5e8:	mulss  0xc(%rdi),%xmm7
  40d5ed:	addss  %xmm5,%xmm4
  40d5f1:	addss  %xmm6,%xmm4
  40d5f5:	addss  %xmm7,%xmm4
  40d5f9:	movss  %xmm4,0x4(%rdx)
  40d5fe:	movss  0x18(%rsi),%xmm8
  40d604:	movss  0x8(%rsi),%xmm9
  40d60a:	mulss  0x4(%rdi),%xmm8
  40d610:	mulss  (%rdi),%xmm9
  40d615:	movss  0x8(%rdi),%xmm10
  40d61b:	mulss  0x28(%rsi),%xmm10
  40d621:	movss  0xc(%rdi),%xmm11
  40d627:	mulss  0x38(%rsi),%xmm11
  40d62d:	addss  %xmm9,%xmm8
  40d632:	addss  %xmm10,%xmm8
  40d637:	addss  %xmm11,%xmm8
  40d63c:	movss  %xmm8,0x8(%rdx)
  40d642:	movss  (%rdi),%xmm12
  40d647:	movss  0x4(%rdi),%xmm13
  40d64d:	mulss  0xc(%rsi),%xmm12
  40d653:	mulss  0x1c(%rsi),%xmm13
  40d659:	movss  0x8(%rdi),%xmm14
  40d65f:	mulss  0x2c(%rsi),%xmm14
  40d665:	movss  0xc(%rdi),%xmm15
  40d66b:	mulss  0x3c(%rsi),%xmm15
  40d671:	addss  %xmm13,%xmm12
  40d676:	addss  %xmm14,%xmm12
  40d67b:	addss  %xmm15,%xmm12
  40d680:	movss  %xmm12,0xc(%rdx)
  40d686:	movss  0x10(%rdi),%xmm0
  40d68b:	movss  0x14(%rdi),%xmm1
  40d690:	mulss  (%rsi),%xmm0
  40d694:	mulss  0x10(%rsi),%xmm1
  40d699:	movss  0x18(%rdi),%xmm2
  40d69e:	mulss  0x20(%rsi),%xmm2
  40d6a3:	movss  0x1c(%rdi),%xmm3
  40d6a8:	mulss  0x30(%rsi),%xmm3
  40d6ad:	addss  %xmm1,%xmm0
  40d6b1:	addss  %xmm2,%xmm0
  40d6b5:	addss  %xmm3,%xmm0
  40d6b9:	movss  %xmm0,0x10(%rdx)
  40d6be:	movss  0x10(%rdi),%xmm4
  40d6c3:	movss  0x14(%rdi),%xmm5
  40d6c8:	mulss  0x4(%rsi),%xmm4
  40d6cd:	mulss  0x14(%rsi),%xmm5
  40d6d2:	movss  0x18(%rdi),%xmm6
  40d6d7:	mulss  0x24(%rsi),%xmm6
  40d6dc:	movss  0x1c(%rdi),%xmm7
  40d6e1:	mulss  0x34(%rsi),%xmm7
  40d6e6:	addss  %xmm5,%xmm4
  40d6ea:	addss  %xmm6,%xmm4
  40d6ee:	addss  %xmm7,%xmm4
  40d6f2:	movss  %xmm4,0x14(%rdx)
  40d6f7:	movss  0x10(%rdi),%xmm8
  40d6fd:	movss  0x14(%rdi),%xmm9
  40d703:	mulss  0x8(%rsi),%xmm8
  40d709:	mulss  0x18(%rsi),%xmm9
  40d70f:	movss  0x18(%rdi),%xmm10
  40d715:	mulss  0x28(%rsi),%xmm10
  40d71b:	movss  0x1c(%rdi),%xmm11
  40d721:	mulss  0x38(%rsi),%xmm11
  40d727:	addss  %xmm9,%xmm8
  40d72c:	addss  %xmm10,%xmm8
  40d731:	addss  %xmm11,%xmm8
  40d736:	movss  %xmm8,0x18(%rdx)
  40d73c:	movss  0x10(%rdi),%xmm12
  40d742:	mulss  0xc(%rsi),%xmm12
  40d748:	movss  0x14(%rdi),%xmm13
  40d74e:	mulss  0x1c(%rsi),%xmm13
  40d754:	movss  0x18(%rdi),%xmm14
  40d75a:	mulss  0x2c(%rsi),%xmm14
  40d760:	movss  0x1c(%rdi),%xmm15
  40d766:	mulss  0x3c(%rsi),%xmm15
  40d76c:	addss  %xmm13,%xmm12
  40d771:	addss  %xmm14,%xmm12
  40d776:	addss  %xmm15,%xmm12
  40d77b:	movss  %xmm12,0x1c(%rdx)
  40d781:	movss  0x20(%rdi),%xmm0
  40d786:	movss  0x24(%rdi),%xmm1
  40d78b:	mulss  (%rsi),%xmm0
  40d78f:	mulss  0x10(%rsi),%xmm1
  40d794:	movss  0x28(%rdi),%xmm2
  40d799:	mulss  0x20(%rsi),%xmm2
  40d79e:	movss  0x2c(%rdi),%xmm3
  40d7a3:	mulss  0x30(%rsi),%xmm3
  40d7a8:	addss  %xmm1,%xmm0
  40d7ac:	addss  %xmm2,%xmm0
  40d7b0:	addss  %xmm3,%xmm0
  40d7b4:	movss  %xmm0,0x20(%rdx)
  40d7b9:	movss  0x20(%rdi),%xmm4
  40d7be:	movss  0x24(%rdi),%xmm5
  40d7c3:	mulss  0x4(%rsi),%xmm4
  40d7c8:	mulss  0x14(%rsi),%xmm5
  40d7cd:	movss  0x28(%rdi),%xmm6
  40d7d2:	mulss  0x24(%rsi),%xmm6
  40d7d7:	movss  0x2c(%rdi),%xmm7
  40d7dc:	mulss  0x34(%rsi),%xmm7
  40d7e1:	addss  %xmm5,%xmm4
  40d7e5:	addss  %xmm6,%xmm4
  40d7e9:	addss  %xmm7,%xmm4
  40d7ed:	movss  %xmm4,0x24(%rdx)
  40d7f2:	movss  0x20(%rdi),%xmm8
  40d7f8:	movss  0x24(%rdi),%xmm9
  40d7fe:	mulss  0x8(%rsi),%xmm8
  40d804:	mulss  0x18(%rsi),%xmm9
  40d80a:	movss  0x28(%rdi),%xmm10
  40d810:	mulss  0x28(%rsi),%xmm10
  40d816:	movss  0x2c(%rdi),%xmm11
  40d81c:	mulss  0x38(%rsi),%xmm11
  40d822:	addss  %xmm9,%xmm8
  40d827:	addss  %xmm10,%xmm8
  40d82c:	addss  %xmm11,%xmm8
  40d831:	movss  %xmm8,0x28(%rdx)
  40d837:	movss  0x20(%rdi),%xmm12
  40d83d:	movss  0x24(%rdi),%xmm13
  40d843:	mulss  0xc(%rsi),%xmm12
  40d849:	mulss  0x1c(%rsi),%xmm13
  40d84f:	movss  0x28(%rdi),%xmm14
  40d855:	mulss  0x2c(%rsi),%xmm14
  40d85b:	movss  0x2c(%rdi),%xmm15
  40d861:	mulss  0x3c(%rsi),%xmm15
  40d867:	addss  %xmm13,%xmm12
  40d86c:	addss  %xmm14,%xmm12
  40d871:	addss  %xmm15,%xmm12
  40d876:	movss  %xmm12,0x2c(%rdx)
  40d87c:	movss  0x30(%rdi),%xmm0
  40d881:	movss  0x34(%rdi),%xmm1
  40d886:	mulss  (%rsi),%xmm0
  40d88a:	mulss  0x10(%rsi),%xmm1
  40d88f:	movss  0x38(%rdi),%xmm2
  40d894:	mulss  0x20(%rsi),%xmm2
  40d899:	movss  0x3c(%rdi),%xmm3
  40d89e:	mulss  0x30(%rsi),%xmm3
  40d8a3:	addss  %xmm1,%xmm0
  40d8a7:	addss  %xmm2,%xmm0
  40d8ab:	addss  %xmm3,%xmm0
  40d8af:	movss  %xmm0,0x30(%rdx)
  40d8b4:	movss  0x30(%rdi),%xmm4
  40d8b9:	movss  0x34(%rdi),%xmm5
  40d8be:	mulss  0x4(%rsi),%xmm4
  40d8c3:	mulss  0x14(%rsi),%xmm5
  40d8c8:	movss  0x38(%rdi),%xmm6
  40d8cd:	mulss  0x24(%rsi),%xmm6
  40d8d2:	movss  0x3c(%rdi),%xmm7
  40d8d7:	mulss  0x34(%rsi),%xmm7
  40d8dc:	addss  %xmm5,%xmm4
  40d8e0:	addss  %xmm6,%xmm4
  40d8e4:	addss  %xmm7,%xmm4
  40d8e8:	movss  %xmm4,0x34(%rdx)
  40d8ed:	movss  0x30(%rdi),%xmm8
  40d8f3:	mulss  0x8(%rsi),%xmm8
  40d8f9:	movss  0x34(%rdi),%xmm9
  40d8ff:	mulss  0x18(%rsi),%xmm9
  40d905:	movss  0x38(%rdi),%xmm10
  40d90b:	mulss  0x28(%rsi),%xmm10
  40d911:	movss  0x3c(%rdi),%xmm11
  40d917:	mulss  0x38(%rsi),%xmm11
  40d91d:	addss  %xmm9,%xmm8
  40d922:	addss  %xmm10,%xmm8
  40d927:	addss  %xmm11,%xmm8
  40d92c:	movss  %xmm8,0x38(%rdx)
  40d932:	movss  0x30(%rdi),%xmm12
  40d938:	movss  0x34(%rdi),%xmm13
  40d93e:	mulss  0xc(%rsi),%xmm12
  40d944:	mulss  0x1c(%rsi),%xmm13
  40d94a:	movss  0x38(%rdi),%xmm14
  40d950:	mulss  0x2c(%rsi),%xmm14
  40d956:	movss  0x3c(%rdi),%xmm15
  40d95c:	mulss  0x3c(%rsi),%xmm15
  40d962:	addss  %xmm13,%xmm12
  40d967:	addss  %xmm14,%xmm12
  40d96c:	addss  %xmm15,%xmm12
  40d971:	movss  %xmm12,0x3c(%rdx)
  40d977:	retq   
  40d978:	nopl   0x0(%rax,%rax,1)

000000000040d980 <Copy_Matrix>:
  40d980:	lea    0x10(%rsi),%rax
  40d984:	cmp    %rax,%rdi
  40d987:	jae    40d992 <Copy_Matrix+0x12>
  40d989:	lea    0x10(%rdi),%rdx
  40d98d:	cmp    %rdx,%rsi
  40d990:	jb     40d9b8 <Copy_Matrix+0x38>
  40d992:	movups (%rdi),%xmm0
  40d995:	movups %xmm0,(%rsi)
  40d998:	movups 0x10(%rdi),%xmm1
  40d99c:	movups %xmm1,0x10(%rsi)
  40d9a0:	movups 0x20(%rdi),%xmm2
  40d9a4:	movups %xmm2,0x20(%rsi)
  40d9a8:	movups 0x30(%rdi),%xmm3
  40d9ac:	movups %xmm3,0x30(%rsi)
  40d9b0:	retq   
  40d9b1:	nopl   0x0(%rax)
  40d9b8:	movss  (%rdi),%xmm0
  40d9bc:	movss  %xmm0,(%rsi)
  40d9c0:	movss  0x4(%rdi),%xmm1
  40d9c5:	movss  %xmm1,0x4(%rsi)
  40d9ca:	movss  0x8(%rdi),%xmm2
  40d9cf:	movss  %xmm2,0x8(%rsi)
  40d9d4:	movss  0xc(%rdi),%xmm3
  40d9d9:	movss  %xmm3,0xc(%rsi)
  40d9de:	movss  0x10(%rdi),%xmm4
  40d9e3:	movss  %xmm4,0x10(%rsi)
  40d9e8:	movss  0x14(%rdi),%xmm5
  40d9ed:	movss  %xmm5,0x14(%rsi)
  40d9f2:	movss  0x18(%rdi),%xmm6
  40d9f7:	movss  %xmm6,0x18(%rsi)
  40d9fc:	movss  0x1c(%rdi),%xmm7
  40da01:	movss  %xmm7,0x1c(%rsi)
  40da06:	movss  0x20(%rdi),%xmm8
  40da0c:	movss  %xmm8,0x20(%rsi)
  40da12:	movss  0x24(%rdi),%xmm9
  40da18:	movss  %xmm9,0x24(%rsi)
  40da1e:	movss  0x28(%rdi),%xmm10
  40da24:	movss  %xmm10,0x28(%rsi)
  40da2a:	movss  0x2c(%rdi),%xmm11
  40da30:	movss  %xmm11,0x2c(%rsi)
  40da36:	movss  0x30(%rdi),%xmm12
  40da3c:	movss  %xmm12,0x30(%rsi)
  40da42:	movss  0x34(%rdi),%xmm13
  40da48:	movss  %xmm13,0x34(%rsi)
  40da4e:	movss  0x38(%rdi),%xmm14
  40da54:	movss  %xmm14,0x38(%rsi)
  40da5a:	movss  0x3c(%rdi),%xmm15
  40da60:	movss  %xmm15,0x3c(%rsi)
  40da66:	retq   

000000000040da67 <TIFFClose>:
  40da67:	push   %rbx
  40da68:	mov    %rdi,%rbx
  40da6b:	cmpw   $0x0,0xa(%rdi)
  40da70:	jne    40dac0 <TIFFClose+0x59>
  40da72:	mov    0x280(%rbx),%rdx
  40da79:	test   %rdx,%rdx
  40da7c:	je     40da88 <TIFFClose+0x21>
  40da7e:	mov    %rbx,%rdi
  40da81:	mov    $0x0,%eax
  40da86:	callq  *%rdx
  40da88:	mov    %rbx,%rdi
  40da8b:	callq  410961 <TIFFFreeDirectory>
  40da90:	mov    0x298(%rbx),%rdi
  40da97:	test   %rdi,%rdi
  40da9a:	je     40daa2 <TIFFClose+0x3b>
  40da9c:	testb  $0x40,0xe(%rbx)
  40daa0:	jne    40dac7 <TIFFClose+0x60>
  40daa2:	testb  $0x1,0xf(%rbx)
  40daa6:	jne    40dace <TIFFClose+0x67>
  40daa8:	movswl 0x8(%rbx),%edi
  40daac:	mov    $0x0,%eax
  40dab1:	callq  4011f0 <close@plt>
  40dab6:	mov    %rbx,%rdi
  40dab9:	callq  4010b0 <free@plt>
  40dabe:	pop    %rbx
  40dabf:	retq   
  40dac0:	callq  412b6c <TIFFFlush>
  40dac5:	jmp    40da72 <TIFFClose+0xb>
  40dac7:	callq  4010b0 <free@plt>
  40dacc:	jmp    40daa2 <TIFFClose+0x3b>
  40dace:	mov    0x2c0(%rbx),%rsi
  40dad5:	mov    0x2b8(%rbx),%rdi
  40dadc:	callq  40db7d <TIFFUnmapFileContents>
  40dae1:	jmp    40daa8 <TIFFClose+0x41>

000000000040dae3 <TIFFGetFileSize>:
  40dae3:	sub    $0x98,%rsp
  40daea:	mov    %edi,%esi
  40daec:	mov    %rsp,%rdx
  40daef:	mov    $0x1,%edi
  40daf4:	callq  401290 <__fxstat@plt>
  40daf9:	mov    $0x0,%edx
  40dafe:	test   %eax,%eax
  40db00:	js     40db07 <TIFFGetFileSize+0x24>
  40db02:	mov    0x30(%rsp),%rdx
  40db07:	mov    %rdx,%rax
  40db0a:	add    $0x98,%rsp
  40db11:	retq   

000000000040db12 <TIFFMapFileContents>:
  40db12:	push   %r13
  40db14:	push   %r12
  40db16:	push   %rbp
  40db17:	push   %rbx
  40db18:	sub    $0x8,%rsp
  40db1c:	mov    %edi,%ebp
  40db1e:	mov    %rsi,%r12
  40db21:	mov    %rdx,%r13
  40db24:	callq  40dae3 <TIFFGetFileSize>
  40db29:	mov    %rax,%rbx
  40db2c:	mov    $0x0,%eax
  40db31:	cmp    $0xffffffffffffffff,%rbx
  40db35:	je     40db72 <TIFFMapFileContents+0x60>
  40db37:	mov    $0x0,%r9d
  40db3d:	mov    %ebp,%r8d
  40db40:	mov    $0x1,%ecx
  40db45:	mov    $0x1,%edx
  40db4a:	mov    %rbx,%rsi
  40db4d:	mov    $0x0,%edi
  40db52:	callq  401150 <mmap@plt>
  40db57:	mov    %rax,%rdx
  40db5a:	mov    %rax,(%r12)
  40db5e:	mov    $0x0,%eax
  40db63:	cmp    $0xffffffffffffffff,%rdx
  40db67:	je     40db72 <TIFFMapFileContents+0x60>
  40db69:	mov    %rbx,0x0(%r13)
  40db6d:	mov    $0x1,%eax
  40db72:	add    $0x8,%rsp
  40db76:	pop    %rbx
  40db77:	pop    %rbp
  40db78:	pop    %r12
  40db7a:	pop    %r13
  40db7c:	retq   

000000000040db7d <TIFFUnmapFileContents>:
  40db7d:	sub    $0x8,%rsp
  40db81:	callq  4012c0 <munmap@plt>
  40db86:	add    $0x8,%rsp
  40db8a:	retq   

000000000040db8b <OkToChangeTag>:
  40db8b:	mov    $0x1,%eax
  40db90:	cmp    $0x101,%esi
  40db96:	je     40db9e <OkToChangeTag+0x13>
  40db98:	testb  $0x8,0xe(%rdi)
  40db9c:	jne    40dba0 <OkToChangeTag+0x15>
  40db9e:	repz retq 
  40dba0:	sub    $0x8,%rsp
  40dba4:	movzwl %si,%edi
  40dba7:	mov    $0x0,%esi
  40dbac:	callq  410e60 <TIFFFindFieldInfo>
  40dbb1:	mov    %rax,%rdx
  40dbb4:	mov    $0x1,%eax
  40dbb9:	test   %rdx,%rdx
  40dbbc:	je     40dbc9 <OkToChangeTag+0x3e>
  40dbbe:	cmpw   $0x0,0xe(%rdx)
  40dbc3:	setne  %al
  40dbc6:	movzbl %al,%eax
  40dbc9:	add    $0x8,%rsp
  40dbcd:	retq   

000000000040dbce <TIFFGetField1>:
  40dbce:	cmp    $0x13b,%esi
  40dbd4:	je     40e3f6 <TIFFGetField1+0x828>
  40dbda:	cmp    $0x13b,%esi
  40dbe0:	jg     40df1b <TIFFGetField1+0x34d>
  40dbe6:	cmp    $0x116,%esi
  40dbec:	je     40e552 <TIFFGetField1+0x984>
  40dbf2:	cmp    $0x116,%esi
  40dbf8:	jle    40dc83 <TIFFGetField1+0xb5>
  40dbfe:	cmp    $0x11e,%esi
  40dc04:	je     40e632 <TIFFGetField1+0xa64>
  40dc0a:	cmp    $0x11e,%esi
  40dc10:	jle    40dde6 <TIFFGetField1+0x218>
  40dc16:	cmp    $0x128,%esi
  40dc1c:	je     40e70a <TIFFGetField1+0xb3c>
  40dc22:	cmp    $0x128,%esi
  40dc28:	jle    40de76 <TIFFGetField1+0x2a8>
  40dc2e:	cmp    $0x12d,%esi
  40dc34:	je     40e276 <TIFFGetField1+0x6a8>
  40dc3a:	cmp    $0x12d,%esi
  40dc40:	jle    40dec4 <TIFFGetField1+0x2f6>
  40dc46:	cmp    $0x131,%esi
  40dc4c:	je     40e4e0 <TIFFGetField1+0x912>
  40dc52:	cmp    $0x132,%esi
  40dc58:	jne    40dd18 <TIFFGetField1+0x14a>
  40dc5e:	mov    (%rdx),%ecx
  40dc60:	cmp    $0x2f,%ecx
  40dc63:	ja     40e428 <TIFFGetField1+0x85a>
  40dc69:	mov    %ecx,%eax
  40dc6b:	add    0x10(%rdx),%rax
  40dc6f:	add    $0x8,%ecx
  40dc72:	mov    %ecx,(%rdx)
  40dc74:	mov    (%rax),%rax
  40dc77:	mov    0xe0(%rdi),%rdx
  40dc7e:	mov    %rdx,(%rax)
  40dc81:	jmp    40dcf2 <TIFFGetField1+0x124>
  40dc83:	cmp    $0x10a,%esi
  40dc89:	je     40e3b6 <TIFFGetField1+0x7e8>
  40dc8f:	cmp    $0x10a,%esi
  40dc95:	jg     40dd41 <TIFFGetField1+0x173>
  40dc9b:	cmp    $0x102,%esi
  40dca1:	je     40e2fa <TIFFGetField1+0x72c>
  40dca7:	cmp    $0x102,%esi
  40dcad:	jg     40dcf4 <TIFFGetField1+0x126>
  40dcaf:	cmp    $0x100,%esi
  40dcb5:	je     40e29c <TIFFGetField1+0x6ce>
  40dcbb:	cmp    $0x100,%esi
  40dcc1:	jg     40e2cb <TIFFGetField1+0x6fd>
  40dcc7:	cmp    $0xfe,%esi
  40dccd:	jne    40dd18 <TIFFGetField1+0x14a>
  40dccf:	movzwl 0x40(%rdi),%eax
  40dcd3:	mov    (%rdx),%ecx
  40dcd5:	cmp    $0x2f,%ecx
  40dcd8:	ja     40e28b <TIFFGetField1+0x6bd>
  40dcde:	mov    %ecx,%esi
  40dce0:	add    0x10(%rdx),%rsi
  40dce4:	add    $0x8,%ecx
  40dce7:	mov    %ecx,(%rdx)
  40dce9:	mov    (%rsi),%rdx
  40dcec:	movzwl %ax,%eax
  40dcef:	mov    %rax,(%rdx)
  40dcf2:	repz retq 
  40dcf4:	cmp    $0x106,%esi
  40dcfa:	je     40e358 <TIFFGetField1+0x78a>
  40dd00:	cmp    $0x107,%esi
  40dd06:	je     40e387 <TIFFGetField1+0x7b9>
  40dd0c:	cmp    $0x103,%esi
  40dd12:	je     40e329 <TIFFGetField1+0x75b>
  40dd18:	sub    $0x8,%rsp
  40dd1c:	movzwl %si,%edi
  40dd1f:	callq  410ebe <TIFFFieldWithTag>
  40dd24:	mov    0x10(%rax),%rdx
  40dd28:	mov    $0x4199c0,%esi
  40dd2d:	mov    $0x419ae2,%edi
  40dd32:	mov    $0x0,%eax
  40dd37:	callq  412a93 <TIFFError>
  40dd3c:	add    $0x8,%rsp
  40dd40:	retq   
  40dd41:	cmp    $0x110,%esi
  40dd47:	je     40e4ae <TIFFGetField1+0x8e0>
  40dd4d:	cmp    $0x110,%esi
  40dd53:	jg     40dd9d <TIFFGetField1+0x1cf>
  40dd55:	cmp    $0x10e,%esi
  40dd5b:	je     40e44a <TIFFGetField1+0x87c>
  40dd61:	cmp    $0x10e,%esi
  40dd67:	jg     40e47c <TIFFGetField1+0x8ae>
  40dd6d:	cmp    $0x10d,%esi
  40dd73:	jne    40dd18 <TIFFGetField1+0x14a>
  40dd75:	mov    (%rdx),%ecx
  40dd77:	cmp    $0x2f,%ecx
  40dd7a:	ja     40e3e5 <TIFFGetField1+0x817>
  40dd80:	mov    %ecx,%eax
  40dd82:	add    0x10(%rdx),%rax
  40dd86:	add    $0x8,%ecx
  40dd89:	mov    %ecx,(%rdx)
  40dd8b:	mov    (%rax),%rax
  40dd8e:	mov    0xd0(%rdi),%rdx
  40dd95:	mov    %rdx,(%rax)
  40dd98:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40dd9d:	cmp    $0x112,%esi
  40dda3:	je     40e512 <TIFFGetField1+0x944>
  40dda9:	cmp    $0x112,%esi
  40ddaf:	jl     40e81c <TIFFGetField1+0xc4e>
  40ddb5:	cmp    $0x115,%esi
  40ddbb:	jne    40dd18 <TIFFGetField1+0x14a>
  40ddc1:	mov    (%rdx),%ecx
  40ddc3:	cmp    $0x2f,%ecx
  40ddc6:	ja     40e541 <TIFFGetField1+0x973>
  40ddcc:	mov    %ecx,%eax
  40ddce:	add    0x10(%rdx),%rax
  40ddd2:	add    $0x8,%ecx
  40ddd5:	mov    %ecx,(%rdx)
  40ddd7:	mov    (%rax),%rax
  40ddda:	movzwl 0x50(%rdi),%edx
  40ddde:	mov    %dx,(%rax)
  40dde1:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40dde6:	cmp    $0x11a,%esi
  40ddec:	je     40e5c1 <TIFFGetField1+0x9f3>
  40ddf2:	cmp    $0x11a,%esi
  40ddf8:	jle    40de39 <TIFFGetField1+0x26b>
  40ddfa:	cmp    $0x11c,%esi
  40de00:	je     40e603 <TIFFGetField1+0xa35>
  40de06:	cmp    $0x11c,%esi
  40de0c:	jg     40e674 <TIFFGetField1+0xaa6>
  40de12:	mov    (%rdx),%ecx
  40de14:	cmp    $0x2f,%ecx
  40de17:	ja     40e5f2 <TIFFGetField1+0xa24>
  40de1d:	mov    %ecx,%eax
  40de1f:	add    0x10(%rdx),%rax
  40de23:	add    $0x8,%ecx
  40de26:	mov    %ecx,(%rdx)
  40de28:	mov    (%rax),%rax
  40de2b:	movss  0x74(%rdi),%xmm0
  40de30:	movss  %xmm0,(%rax)
  40de34:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40de39:	cmp    $0x118,%esi
  40de3f:	je     40e581 <TIFFGetField1+0x9b3>
  40de45:	cmp    $0x118,%esi
  40de4b:	jle    40e84e <TIFFGetField1+0xc80>
  40de51:	mov    0x68(%rdi),%rcx
  40de55:	mov    (%rdx),%eax
  40de57:	cmp    $0x2f,%eax
  40de5a:	ja     40e5b0 <TIFFGetField1+0x9e2>
  40de60:	mov    %eax,%esi
  40de62:	add    0x10(%rdx),%rsi
  40de66:	add    $0x8,%eax
  40de69:	mov    %eax,(%rdx)
  40de6b:	mov    (%rsi),%rax
  40de6e:	mov    %cx,(%rax)
  40de71:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40de76:	cmp    $0x124,%esi
  40de7c:	je     40e6a6 <TIFFGetField1+0xad8>
  40de82:	cmp    $0x125,%esi
  40de88:	je     40e6d8 <TIFFGetField1+0xb0a>
  40de8e:	cmp    $0x11f,%esi
  40de94:	jne    40dd18 <TIFFGetField1+0x14a>
  40de9a:	mov    (%rdx),%ecx
  40de9c:	cmp    $0x2f,%ecx
  40de9f:	ja     40e663 <TIFFGetField1+0xa95>
  40dea5:	mov    %ecx,%eax
  40dea7:	add    0x10(%rdx),%rax
  40deab:	add    $0x8,%ecx
  40deae:	mov    %ecx,(%rdx)
  40deb0:	mov    (%rax),%rax
  40deb3:	movss  0x80(%rdi),%xmm0
  40debb:	movss  %xmm0,(%rax)
  40debf:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40dec4:	cmp    $0x129,%esi
  40deca:	jne    40dd18 <TIFFGetField1+0x14a>
  40ded0:	mov    (%rdx),%ecx
  40ded2:	cmp    $0x2f,%ecx
  40ded5:	ja     40e739 <TIFFGetField1+0xb6b>
  40dedb:	mov    %ecx,%eax
  40dedd:	add    0x10(%rdx),%rax
  40dee1:	add    $0x8,%ecx
  40dee4:	mov    %ecx,(%rdx)
  40dee6:	mov    (%rax),%rax
  40dee9:	movzwl 0x98(%rdi),%ecx
  40def0:	mov    %cx,(%rax)
  40def3:	mov    (%rdx),%eax
  40def5:	cmp    $0x2f,%eax
  40def8:	ja     40e74a <TIFFGetField1+0xb7c>
  40defe:	mov    %eax,%ecx
  40df00:	add    0x10(%rdx),%rcx
  40df04:	add    $0x8,%eax
  40df07:	mov    %eax,(%rdx)
  40df09:	mov    (%rcx),%rax
  40df0c:	movzwl 0x9a(%rdi),%edx
  40df13:	mov    %dx,(%rax)
  40df16:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40df1b:	cmp    $0x150,%esi
  40df21:	je     40ecb1 <TIFFGetField1+0x10e3>
  40df27:	cmp    $0x150,%esi
  40df2d:	jle    40dfb8 <TIFFGetField1+0x3ea>
  40df33:	cmp    $0x209,%esi
  40df39:	je     40eb77 <TIFFGetField1+0xfa9>
  40df3f:	cmp    $0x209,%esi
  40df45:	jle    40e14d <TIFFGetField1+0x57f>
  40df4b:	cmp    $0x214,%esi
  40df51:	je     40ec4d <TIFFGetField1+0x107f>
  40df57:	cmp    $0x214,%esi
  40df5d:	jle    40e1f6 <TIFFGetField1+0x628>
  40df63:	cmp    $0x80e4,%esi
  40df69:	je     40e9b3 <TIFFGetField1+0xde5>
  40df6f:	cmp    $0x80e4,%esi
  40df75:	jle    40e242 <TIFFGetField1+0x674>
  40df7b:	cmp    $0x80e5,%esi
  40df81:	je     40e9ff <TIFFGetField1+0xe31>
  40df87:	cmp    $0x80e6,%esi
  40df8d:	jne    40dd18 <TIFFGetField1+0x14a>
  40df93:	mov    (%rdx),%ecx
  40df95:	cmp    $0x2f,%ecx
  40df98:	ja     40e9a2 <TIFFGetField1+0xdd4>
  40df9e:	mov    %ecx,%eax
  40dfa0:	add    0x10(%rdx),%rax
  40dfa4:	add    $0x8,%ecx
  40dfa7:	mov    %ecx,(%rdx)
  40dfa9:	mov    (%rax),%rax
  40dfac:	mov    0x38(%rdi),%rdx
  40dfb0:	mov    %rdx,(%rax)
  40dfb3:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40dfb8:	cmp    $0x143,%esi
  40dfbe:	je     40e973 <TIFFGetField1+0xda5>
  40dfc4:	cmp    $0x143,%esi
  40dfca:	jg     40e0aa <TIFFGetField1+0x4dc>
  40dfd0:	cmp    $0x13f,%esi
  40dfd6:	je     40ebdb <TIFFGetField1+0x100d>
  40dfdc:	cmp    $0x13f,%esi
  40dfe2:	jg     40e024 <TIFFGetField1+0x456>
  40dfe4:	cmp    $0x13d,%esi
  40dfea:	je     40e7ed <TIFFGetField1+0xc1f>
  40dff0:	cmp    $0x13d,%esi
  40dff6:	jg     40eba9 <TIFFGetField1+0xfdb>
  40dffc:	mov    (%rdx),%ecx
  40dffe:	cmp    $0x2f,%ecx
  40e001:	ja     40e439 <TIFFGetField1+0x86b>
  40e007:	mov    %ecx,%eax
  40e009:	add    0x10(%rdx),%rax
  40e00d:	add    $0x8,%ecx
  40e010:	mov    %ecx,(%rdx)
  40e012:	mov    (%rax),%rax
  40e015:	mov    0xe8(%rdi),%rdx
  40e01c:	mov    %rdx,(%rax)
  40e01f:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e024:	cmp    $0x141,%esi
  40e02a:	je     40e75b <TIFFGetField1+0xb8d>
  40e030:	cmp    $0x141,%esi
  40e036:	jg     40e944 <TIFFGetField1+0xd76>
  40e03c:	mov    (%rdx),%ecx
  40e03e:	cmp    $0x2f,%ecx
  40e041:	ja     40e7ba <TIFFGetField1+0xbec>
  40e047:	mov    %ecx,%eax
  40e049:	add    0x10(%rdx),%rax
  40e04d:	add    $0x8,%ecx
  40e050:	mov    %ecx,(%rdx)
  40e052:	mov    (%rax),%rax
  40e055:	mov    0xb0(%rdi),%rcx
  40e05c:	mov    %rcx,(%rax)
  40e05f:	mov    (%rdx),%eax
  40e061:	cmp    $0x2f,%eax
  40e064:	ja     40e7cb <TIFFGetField1+0xbfd>
  40e06a:	mov    %eax,%ecx
  40e06c:	add    0x10(%rdx),%rcx
  40e070:	add    $0x8,%eax
  40e073:	mov    %eax,(%rdx)
  40e075:	mov    (%rcx),%rax
  40e078:	mov    0xb8(%rdi),%rcx
  40e07f:	mov    %rcx,(%rax)
  40e082:	mov    (%rdx),%eax
  40e084:	cmp    $0x2f,%eax
  40e087:	ja     40e7dc <TIFFGetField1+0xc0e>
  40e08d:	mov    %eax,%ecx
  40e08f:	add    0x10(%rdx),%rcx
  40e093:	add    $0x8,%eax
  40e096:	mov    %eax,(%rdx)
  40e098:	mov    (%rcx),%rax
  40e09b:	mov    0xc0(%rdi),%rdx
  40e0a2:	mov    %rdx,(%rax)
  40e0a5:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e0aa:	cmp    $0x147,%esi
  40e0b0:	je     40e901 <TIFFGetField1+0xd33>
  40e0b6:	cmp    $0x147,%esi
  40e0bc:	jle    40e10d <TIFFGetField1+0x53f>
  40e0be:	cmp    $0x14c,%esi
  40e0c4:	je     40ec7f <TIFFGetField1+0x10b1>
  40e0ca:	cmp    $0x14d,%esi
  40e0d0:	je     40ed10 <TIFFGetField1+0x1142>
  40e0d6:	cmp    $0x148,%esi
  40e0dc:	jne    40dd18 <TIFFGetField1+0x14a>
  40e0e2:	movzwl 0xa0(%rdi),%eax
  40e0e9:	mov    (%rdx),%ecx
  40e0eb:	cmp    $0x2f,%ecx
  40e0ee:	ja     40e933 <TIFFGetField1+0xd65>
  40e0f4:	mov    %ecx,%esi
  40e0f6:	add    0x10(%rdx),%rsi
  40e0fa:	add    $0x8,%ecx
  40e0fd:	mov    %ecx,(%rdx)
  40e0ff:	mov    (%rsi),%rdx
  40e102:	movzwl %ax,%eax
  40e105:	mov    %rax,(%rdx)
  40e108:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e10d:	cmp    $0x145,%esi
  40e113:	je     40e84e <TIFFGetField1+0xc80>
  40e119:	cmp    $0x145,%esi
  40e11f:	jle    40e81c <TIFFGetField1+0xc4e>
  40e125:	mov    (%rdx),%ecx
  40e127:	cmp    $0x2f,%ecx
  40e12a:	ja     40e8f0 <TIFFGetField1+0xd22>
  40e130:	mov    %ecx,%eax
  40e132:	add    0x10(%rdx),%rax
  40e136:	add    $0x8,%ecx
  40e139:	mov    %ecx,(%rdx)
  40e13b:	mov    (%rax),%rax
  40e13e:	mov    0xa8(%rdi),%rdx
  40e145:	mov    %rdx,(%rax)
  40e148:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e14d:	cmp    $0x200,%esi
  40e153:	je     40ead0 <TIFFGetField1+0xf02>
  40e159:	cmp    $0x200,%esi
  40e15f:	jg     40e1aa <TIFFGetField1+0x5dc>
  40e161:	cmp    $0x152,%esi
  40e167:	je     40e891 <TIFFGetField1+0xcc3>
  40e16d:	cmp    $0x152,%esi
  40e173:	jl     40ed42 <TIFFGetField1+0x1174>
  40e179:	cmp    $0x153,%esi
  40e17f:	jne    40dd18 <TIFFGetField1+0x14a>
  40e185:	mov    (%rdx),%ecx
  40e187:	cmp    $0x2f,%ecx
  40e18a:	ja     40e9ee <TIFFGetField1+0xe20>
  40e190:	mov    %ecx,%eax
  40e192:	add    0x10(%rdx),%rax
  40e196:	add    $0x8,%ecx
  40e199:	mov    %ecx,(%rdx)
  40e19b:	mov    (%rax),%rax
  40e19e:	movzwl 0x44(%rdi),%edx
  40e1a2:	mov    %dx,(%rax)
  40e1a5:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e1aa:	cmp    $0x207,%esi
  40e1b0:	je     40eb13 <TIFFGetField1+0xf45>
  40e1b6:	cmp    $0x207,%esi
  40e1bc:	jg     40eb45 <TIFFGetField1+0xf77>
  40e1c2:	cmp    $0x203,%esi
  40e1c8:	jne    40dd18 <TIFFGetField1+0x14a>
  40e1ce:	mov    (%rdx),%ecx
  40e1d0:	cmp    $0x2f,%ecx
  40e1d3:	ja     40eb02 <TIFFGetField1+0xf34>
  40e1d9:	mov    %ecx,%eax
  40e1db:	add    0x10(%rdx),%rax
  40e1df:	add    $0x8,%ecx
  40e1e2:	mov    %ecx,(%rdx)
  40e1e4:	mov    (%rax),%rax
  40e1e7:	movzwl 0x148(%rdi),%edx
  40e1ee:	mov    %dx,(%rax)
  40e1f1:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e1f6:	cmp    $0x212,%esi
  40e1fc:	je     40ea71 <TIFFGetField1+0xea3>
  40e202:	cmp    $0x212,%esi
  40e208:	jg     40ea3f <TIFFGetField1+0xe71>
  40e20e:	cmp    $0x211,%esi
  40e214:	jne    40dd18 <TIFFGetField1+0x14a>
  40e21a:	mov    (%rdx),%ecx
  40e21c:	cmp    $0x2f,%ecx
  40e21f:	ja     40ea2e <TIFFGetField1+0xe60>
  40e225:	mov    %ecx,%eax
  40e227:	add    0x10(%rdx),%rax
  40e22b:	add    $0x8,%ecx
  40e22e:	mov    %ecx,(%rdx)
  40e230:	mov    (%rax),%rax
  40e233:	mov    0x138(%rdi),%rdx
  40e23a:	mov    %rdx,(%rax)
  40e23d:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e242:	cmp    $0x80e3,%esi
  40e248:	jne    40dd18 <TIFFGetField1+0x14a>
  40e24e:	mov    (%rdx),%ecx
  40e250:	cmp    $0x2f,%ecx
  40e253:	ja     40e880 <TIFFGetField1+0xcb2>
  40e259:	mov    %ecx,%eax
  40e25b:	add    0x10(%rdx),%rax
  40e25f:	add    $0x8,%ecx
  40e262:	mov    %ecx,(%rdx)
  40e264:	mov    (%rax),%rax
  40e267:	movzwl 0x9c(%rdi),%edx
  40e26e:	mov    %dx,(%rax)
  40e271:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e276:	mov    $0x1,%eax
  40e27b:	cmpw   $0x0,0x50(%rdi)
  40e280:	jne    40ec39 <TIFFGetField1+0x106b>
  40e286:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e28b:	mov    0x8(%rdx),%rsi
  40e28f:	lea    0x8(%rsi),%rcx
  40e293:	mov    %rcx,0x8(%rdx)
  40e297:	jmpq   40dce9 <TIFFGetField1+0x11b>
  40e29c:	mov    (%rdx),%ecx
  40e29e:	cmp    $0x2f,%ecx
  40e2a1:	ja     40e2bd <TIFFGetField1+0x6ef>
  40e2a3:	mov    %ecx,%eax
  40e2a5:	add    0x10(%rdx),%rax
  40e2a9:	add    $0x8,%ecx
  40e2ac:	mov    %ecx,(%rdx)
  40e2ae:	mov    (%rax),%rax
  40e2b1:	mov    0x10(%rdi),%rdx
  40e2b5:	mov    %rdx,(%rax)
  40e2b8:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e2bd:	mov    0x8(%rdx),%rax
  40e2c1:	lea    0x8(%rax),%rcx
  40e2c5:	mov    %rcx,0x8(%rdx)
  40e2c9:	jmp    40e2ae <TIFFGetField1+0x6e0>
  40e2cb:	mov    (%rdx),%ecx
  40e2cd:	cmp    $0x2f,%ecx
  40e2d0:	ja     40e2ec <TIFFGetField1+0x71e>
  40e2d2:	mov    %ecx,%eax
  40e2d4:	add    0x10(%rdx),%rax
  40e2d8:	add    $0x8,%ecx
  40e2db:	mov    %ecx,(%rdx)
  40e2dd:	mov    (%rax),%rax
  40e2e0:	mov    0x18(%rdi),%rdx
  40e2e4:	mov    %rdx,(%rax)
  40e2e7:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e2ec:	mov    0x8(%rdx),%rax
  40e2f0:	lea    0x8(%rax),%rcx
  40e2f4:	mov    %rcx,0x8(%rdx)
  40e2f8:	jmp    40e2dd <TIFFGetField1+0x70f>
  40e2fa:	mov    (%rdx),%ecx
  40e2fc:	cmp    $0x2f,%ecx
  40e2ff:	ja     40e31b <TIFFGetField1+0x74d>
  40e301:	mov    %ecx,%eax
  40e303:	add    0x10(%rdx),%rax
  40e307:	add    $0x8,%ecx
  40e30a:	mov    %ecx,(%rdx)
  40e30c:	mov    (%rax),%rax
  40e30f:	movzwl 0x42(%rdi),%edx
  40e313:	mov    %dx,(%rax)
  40e316:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e31b:	mov    0x8(%rdx),%rax
  40e31f:	lea    0x8(%rax),%rcx
  40e323:	mov    %rcx,0x8(%rdx)
  40e327:	jmp    40e30c <TIFFGetField1+0x73e>
  40e329:	mov    (%rdx),%ecx
  40e32b:	cmp    $0x2f,%ecx
  40e32e:	ja     40e34a <TIFFGetField1+0x77c>
  40e330:	mov    %ecx,%eax
  40e332:	add    0x10(%rdx),%rax
  40e336:	add    $0x8,%ecx
  40e339:	mov    %ecx,(%rdx)
  40e33b:	mov    (%rax),%rax
  40e33e:	movzwl 0x46(%rdi),%edx
  40e342:	mov    %dx,(%rax)
  40e345:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e34a:	mov    0x8(%rdx),%rax
  40e34e:	lea    0x8(%rax),%rcx
  40e352:	mov    %rcx,0x8(%rdx)
  40e356:	jmp    40e33b <TIFFGetField1+0x76d>
  40e358:	mov    (%rdx),%ecx
  40e35a:	cmp    $0x2f,%ecx
  40e35d:	ja     40e379 <TIFFGetField1+0x7ab>
  40e35f:	mov    %ecx,%eax
  40e361:	add    0x10(%rdx),%rax
  40e365:	add    $0x8,%ecx
  40e368:	mov    %ecx,(%rdx)
  40e36a:	mov    (%rax),%rax
  40e36d:	movzwl 0x48(%rdi),%edx
  40e371:	mov    %dx,(%rax)
  40e374:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e379:	mov    0x8(%rdx),%rax
  40e37d:	lea    0x8(%rax),%rcx
  40e381:	mov    %rcx,0x8(%rdx)
  40e385:	jmp    40e36a <TIFFGetField1+0x79c>
  40e387:	mov    (%rdx),%ecx
  40e389:	cmp    $0x2f,%ecx
  40e38c:	ja     40e3a8 <TIFFGetField1+0x7da>
  40e38e:	mov    %ecx,%eax
  40e390:	add    0x10(%rdx),%rax
  40e394:	add    $0x8,%ecx
  40e397:	mov    %ecx,(%rdx)
  40e399:	mov    (%rax),%rax
  40e39c:	movzwl 0x4a(%rdi),%edx
  40e3a0:	mov    %dx,(%rax)
  40e3a3:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e3a8:	mov    0x8(%rdx),%rax
  40e3ac:	lea    0x8(%rax),%rcx
  40e3b0:	mov    %rcx,0x8(%rdx)
  40e3b4:	jmp    40e399 <TIFFGetField1+0x7cb>
  40e3b6:	mov    (%rdx),%ecx
  40e3b8:	cmp    $0x2f,%ecx
  40e3bb:	ja     40e3d7 <TIFFGetField1+0x809>
  40e3bd:	mov    %ecx,%eax
  40e3bf:	add    0x10(%rdx),%rax
  40e3c3:	add    $0x8,%ecx
  40e3c6:	mov    %ecx,(%rdx)
  40e3c8:	mov    (%rax),%rax
  40e3cb:	movzwl 0x4c(%rdi),%edx
  40e3cf:	mov    %dx,(%rax)
  40e3d2:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e3d7:	mov    0x8(%rdx),%rax
  40e3db:	lea    0x8(%rax),%rcx
  40e3df:	mov    %rcx,0x8(%rdx)
  40e3e3:	jmp    40e3c8 <TIFFGetField1+0x7fa>
  40e3e5:	mov    0x8(%rdx),%rax
  40e3e9:	lea    0x8(%rax),%rcx
  40e3ed:	mov    %rcx,0x8(%rdx)
  40e3f1:	jmpq   40dd8b <TIFFGetField1+0x1bd>
  40e3f6:	mov    (%rdx),%ecx
  40e3f8:	cmp    $0x2f,%ecx
  40e3fb:	ja     40e41a <TIFFGetField1+0x84c>
  40e3fd:	mov    %ecx,%eax
  40e3ff:	add    0x10(%rdx),%rax
  40e403:	add    $0x8,%ecx
  40e406:	mov    %ecx,(%rdx)
  40e408:	mov    (%rax),%rax
  40e40b:	mov    0xd8(%rdi),%rdx
  40e412:	mov    %rdx,(%rax)
  40e415:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e41a:	mov    0x8(%rdx),%rax
  40e41e:	lea    0x8(%rax),%rcx
  40e422:	mov    %rcx,0x8(%rdx)
  40e426:	jmp    40e408 <TIFFGetField1+0x83a>
  40e428:	mov    0x8(%rdx),%rax
  40e42c:	lea    0x8(%rax),%rcx
  40e430:	mov    %rcx,0x8(%rdx)
  40e434:	jmpq   40dc74 <TIFFGetField1+0xa6>
  40e439:	mov    0x8(%rdx),%rax
  40e43d:	lea    0x8(%rax),%rcx
  40e441:	mov    %rcx,0x8(%rdx)
  40e445:	jmpq   40e012 <TIFFGetField1+0x444>
  40e44a:	mov    (%rdx),%ecx
  40e44c:	cmp    $0x2f,%ecx
  40e44f:	ja     40e46e <TIFFGetField1+0x8a0>
  40e451:	mov    %ecx,%eax
  40e453:	add    0x10(%rdx),%rax
  40e457:	add    $0x8,%ecx
  40e45a:	mov    %ecx,(%rdx)
  40e45c:	mov    (%rax),%rax
  40e45f:	mov    0xf0(%rdi),%rdx
  40e466:	mov    %rdx,(%rax)
  40e469:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e46e:	mov    0x8(%rdx),%rax
  40e472:	lea    0x8(%rax),%rcx
  40e476:	mov    %rcx,0x8(%rdx)
  40e47a:	jmp    40e45c <TIFFGetField1+0x88e>
  40e47c:	mov    (%rdx),%ecx
  40e47e:	cmp    $0x2f,%ecx
  40e481:	ja     40e4a0 <TIFFGetField1+0x8d2>
  40e483:	mov    %ecx,%eax
  40e485:	add    0x10(%rdx),%rax
  40e489:	add    $0x8,%ecx
  40e48c:	mov    %ecx,(%rdx)
  40e48e:	mov    (%rax),%rax
  40e491:	mov    0xf8(%rdi),%rdx
  40e498:	mov    %rdx,(%rax)
  40e49b:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e4a0:	mov    0x8(%rdx),%rax
  40e4a4:	lea    0x8(%rax),%rcx
  40e4a8:	mov    %rcx,0x8(%rdx)
  40e4ac:	jmp    40e48e <TIFFGetField1+0x8c0>
  40e4ae:	mov    (%rdx),%ecx
  40e4b0:	cmp    $0x2f,%ecx
  40e4b3:	ja     40e4d2 <TIFFGetField1+0x904>
  40e4b5:	mov    %ecx,%eax
  40e4b7:	add    0x10(%rdx),%rax
  40e4bb:	add    $0x8,%ecx
  40e4be:	mov    %ecx,(%rdx)
  40e4c0:	mov    (%rax),%rax
  40e4c3:	mov    0x100(%rdi),%rdx
  40e4ca:	mov    %rdx,(%rax)
  40e4cd:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e4d2:	mov    0x8(%rdx),%rax
  40e4d6:	lea    0x8(%rax),%rcx
  40e4da:	mov    %rcx,0x8(%rdx)
  40e4de:	jmp    40e4c0 <TIFFGetField1+0x8f2>
  40e4e0:	mov    (%rdx),%ecx
  40e4e2:	cmp    $0x2f,%ecx
  40e4e5:	ja     40e504 <TIFFGetField1+0x936>
  40e4e7:	mov    %ecx,%eax
  40e4e9:	add    0x10(%rdx),%rax
  40e4ed:	add    $0x8,%ecx
  40e4f0:	mov    %ecx,(%rdx)
  40e4f2:	mov    (%rax),%rax
  40e4f5:	mov    0x108(%rdi),%rdx
  40e4fc:	mov    %rdx,(%rax)
  40e4ff:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e504:	mov    0x8(%rdx),%rax
  40e508:	lea    0x8(%rax),%rcx
  40e50c:	mov    %rcx,0x8(%rdx)
  40e510:	jmp    40e4f2 <TIFFGetField1+0x924>
  40e512:	mov    (%rdx),%ecx
  40e514:	cmp    $0x2f,%ecx
  40e517:	ja     40e533 <TIFFGetField1+0x965>
  40e519:	mov    %ecx,%eax
  40e51b:	add    0x10(%rdx),%rax
  40e51f:	add    $0x8,%ecx
  40e522:	mov    %ecx,(%rdx)
  40e524:	mov    (%rax),%rax
  40e527:	movzwl 0x4e(%rdi),%edx
  40e52b:	mov    %dx,(%rax)
  40e52e:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e533:	mov    0x8(%rdx),%rax
  40e537:	lea    0x8(%rax),%rcx
  40e53b:	mov    %rcx,0x8(%rdx)
  40e53f:	jmp    40e524 <TIFFGetField1+0x956>
  40e541:	mov    0x8(%rdx),%rax
  40e545:	lea    0x8(%rax),%rcx
  40e549:	mov    %rcx,0x8(%rdx)
  40e54d:	jmpq   40ddd7 <TIFFGetField1+0x209>
  40e552:	mov    (%rdx),%ecx
  40e554:	cmp    $0x2f,%ecx
  40e557:	ja     40e573 <TIFFGetField1+0x9a5>
  40e559:	mov    %ecx,%eax
  40e55b:	add    0x10(%rdx),%rax
  40e55f:	add    $0x8,%ecx
  40e562:	mov    %ecx,(%rdx)
  40e564:	mov    (%rax),%rax
  40e567:	mov    0x58(%rdi),%rdx
  40e56b:	mov    %rdx,(%rax)
  40e56e:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e573:	mov    0x8(%rdx),%rax
  40e577:	lea    0x8(%rax),%rcx
  40e57b:	mov    %rcx,0x8(%rdx)
  40e57f:	jmp    40e564 <TIFFGetField1+0x996>
  40e581:	mov    0x60(%rdi),%rcx
  40e585:	mov    (%rdx),%eax
  40e587:	cmp    $0x2f,%eax
  40e58a:	ja     40e5a2 <TIFFGetField1+0x9d4>
  40e58c:	mov    %eax,%esi
  40e58e:	add    0x10(%rdx),%rsi
  40e592:	add    $0x8,%eax
  40e595:	mov    %eax,(%rdx)
  40e597:	mov    (%rsi),%rax
  40e59a:	mov    %cx,(%rax)
  40e59d:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e5a2:	mov    0x8(%rdx),%rsi
  40e5a6:	lea    0x8(%rsi),%rax
  40e5aa:	mov    %rax,0x8(%rdx)
  40e5ae:	jmp    40e597 <TIFFGetField1+0x9c9>
  40e5b0:	mov    0x8(%rdx),%rsi
  40e5b4:	lea    0x8(%rsi),%rax
  40e5b8:	mov    %rax,0x8(%rdx)
  40e5bc:	jmpq   40de6b <TIFFGetField1+0x29d>
  40e5c1:	mov    (%rdx),%ecx
  40e5c3:	cmp    $0x2f,%ecx
  40e5c6:	ja     40e5e4 <TIFFGetField1+0xa16>
  40e5c8:	mov    %ecx,%eax
  40e5ca:	add    0x10(%rdx),%rax
  40e5ce:	add    $0x8,%ecx
  40e5d1:	mov    %ecx,(%rdx)
  40e5d3:	mov    (%rax),%rax
  40e5d6:	movss  0x70(%rdi),%xmm0
  40e5db:	movss  %xmm0,(%rax)
  40e5df:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e5e4:	mov    0x8(%rdx),%rax
  40e5e8:	lea    0x8(%rax),%rcx
  40e5ec:	mov    %rcx,0x8(%rdx)
  40e5f0:	jmp    40e5d3 <TIFFGetField1+0xa05>
  40e5f2:	mov    0x8(%rdx),%rax
  40e5f6:	lea    0x8(%rax),%rcx
  40e5fa:	mov    %rcx,0x8(%rdx)
  40e5fe:	jmpq   40de28 <TIFFGetField1+0x25a>
  40e603:	mov    (%rdx),%ecx
  40e605:	cmp    $0x2f,%ecx
  40e608:	ja     40e624 <TIFFGetField1+0xa56>
  40e60a:	mov    %ecx,%eax
  40e60c:	add    0x10(%rdx),%rax
  40e610:	add    $0x8,%ecx
  40e613:	mov    %ecx,(%rdx)
  40e615:	mov    (%rax),%rax
  40e618:	movzwl 0x7a(%rdi),%edx
  40e61c:	mov    %dx,(%rax)
  40e61f:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e624:	mov    0x8(%rdx),%rax
  40e628:	lea    0x8(%rax),%rcx
  40e62c:	mov    %rcx,0x8(%rdx)
  40e630:	jmp    40e615 <TIFFGetField1+0xa47>
  40e632:	mov    (%rdx),%ecx
  40e634:	cmp    $0x2f,%ecx
  40e637:	ja     40e655 <TIFFGetField1+0xa87>
  40e639:	mov    %ecx,%eax
  40e63b:	add    0x10(%rdx),%rax
  40e63f:	add    $0x8,%ecx
  40e642:	mov    %ecx,(%rdx)
  40e644:	mov    (%rax),%rax
  40e647:	movss  0x7c(%rdi),%xmm0
  40e64c:	movss  %xmm0,(%rax)
  40e650:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e655:	mov    0x8(%rdx),%rax
  40e659:	lea    0x8(%rax),%rcx
  40e65d:	mov    %rcx,0x8(%rdx)
  40e661:	jmp    40e644 <TIFFGetField1+0xa76>
  40e663:	mov    0x8(%rdx),%rax
  40e667:	lea    0x8(%rax),%rcx
  40e66b:	mov    %rcx,0x8(%rdx)
  40e66f:	jmpq   40deb0 <TIFFGetField1+0x2e2>
  40e674:	mov    (%rdx),%ecx
  40e676:	cmp    $0x2f,%ecx
  40e679:	ja     40e698 <TIFFGetField1+0xaca>
  40e67b:	mov    %ecx,%eax
  40e67d:	add    0x10(%rdx),%rax
  40e681:	add    $0x8,%ecx
  40e684:	mov    %ecx,(%rdx)
  40e686:	mov    (%rax),%rax
  40e689:	mov    0x110(%rdi),%rdx
  40e690:	mov    %rdx,(%rax)
  40e693:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e698:	mov    0x8(%rdx),%rax
  40e69c:	lea    0x8(%rax),%rcx
  40e6a0:	mov    %rcx,0x8(%rdx)
  40e6a4:	jmp    40e686 <TIFFGetField1+0xab8>
  40e6a6:	mov    (%rdx),%ecx
  40e6a8:	cmp    $0x2f,%ecx
  40e6ab:	ja     40e6ca <TIFFGetField1+0xafc>
  40e6ad:	mov    %ecx,%eax
  40e6af:	add    0x10(%rdx),%rax
  40e6b3:	add    $0x8,%ecx
  40e6b6:	mov    %ecx,(%rdx)
  40e6b8:	mov    (%rax),%rax
  40e6bb:	mov    0x88(%rdi),%rdx
  40e6c2:	mov    %rdx,(%rax)
  40e6c5:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e6ca:	mov    0x8(%rdx),%rax
  40e6ce:	lea    0x8(%rax),%rcx
  40e6d2:	mov    %rcx,0x8(%rdx)
  40e6d6:	jmp    40e6b8 <TIFFGetField1+0xaea>
  40e6d8:	mov    (%rdx),%ecx
  40e6da:	cmp    $0x2f,%ecx
  40e6dd:	ja     40e6fc <TIFFGetField1+0xb2e>
  40e6df:	mov    %ecx,%eax
  40e6e1:	add    0x10(%rdx),%rax
  40e6e5:	add    $0x8,%ecx
  40e6e8:	mov    %ecx,(%rdx)
  40e6ea:	mov    (%rax),%rax
  40e6ed:	mov    0x90(%rdi),%rdx
  40e6f4:	mov    %rdx,(%rax)
  40e6f7:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e6fc:	mov    0x8(%rdx),%rax
  40e700:	lea    0x8(%rax),%rcx
  40e704:	mov    %rcx,0x8(%rdx)
  40e708:	jmp    40e6ea <TIFFGetField1+0xb1c>
  40e70a:	mov    (%rdx),%ecx
  40e70c:	cmp    $0x2f,%ecx
  40e70f:	ja     40e72b <TIFFGetField1+0xb5d>
  40e711:	mov    %ecx,%eax
  40e713:	add    0x10(%rdx),%rax
  40e717:	add    $0x8,%ecx
  40e71a:	mov    %ecx,(%rdx)
  40e71c:	mov    (%rax),%rax
  40e71f:	movzwl 0x78(%rdi),%edx
  40e723:	mov    %dx,(%rax)
  40e726:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e72b:	mov    0x8(%rdx),%rax
  40e72f:	lea    0x8(%rax),%rcx
  40e733:	mov    %rcx,0x8(%rdx)
  40e737:	jmp    40e71c <TIFFGetField1+0xb4e>
  40e739:	mov    0x8(%rdx),%rax
  40e73d:	lea    0x8(%rax),%rcx
  40e741:	mov    %rcx,0x8(%rdx)
  40e745:	jmpq   40dee6 <TIFFGetField1+0x318>
  40e74a:	mov    0x8(%rdx),%rcx
  40e74e:	lea    0x8(%rcx),%rax
  40e752:	mov    %rax,0x8(%rdx)
  40e756:	jmpq   40df09 <TIFFGetField1+0x33b>
  40e75b:	mov    (%rdx),%ecx
  40e75d:	cmp    $0x2f,%ecx
  40e760:	ja     40e79e <TIFFGetField1+0xbd0>
  40e762:	mov    %ecx,%eax
  40e764:	add    0x10(%rdx),%rax
  40e768:	add    $0x8,%ecx
  40e76b:	mov    %ecx,(%rdx)
  40e76d:	mov    (%rax),%rax
  40e770:	movzwl 0xc8(%rdi),%ecx
  40e777:	mov    %cx,(%rax)
  40e77a:	mov    (%rdx),%eax
  40e77c:	cmp    $0x2f,%eax
  40e77f:	ja     40e7ac <TIFFGetField1+0xbde>
  40e781:	mov    %eax,%ecx
  40e783:	add    0x10(%rdx),%rcx
  40e787:	add    $0x8,%eax
  40e78a:	mov    %eax,(%rdx)
  40e78c:	mov    (%rcx),%rax
  40e78f:	movzwl 0xca(%rdi),%edx
  40e796:	mov    %dx,(%rax)
  40e799:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e79e:	mov    0x8(%rdx),%rax
  40e7a2:	lea    0x8(%rax),%rcx
  40e7a6:	mov    %rcx,0x8(%rdx)
  40e7aa:	jmp    40e76d <TIFFGetField1+0xb9f>
  40e7ac:	mov    0x8(%rdx),%rcx
  40e7b0:	lea    0x8(%rcx),%rax
  40e7b4:	mov    %rax,0x8(%rdx)
  40e7b8:	jmp    40e78c <TIFFGetField1+0xbbe>
  40e7ba:	mov    0x8(%rdx),%rax
  40e7be:	lea    0x8(%rax),%rcx
  40e7c2:	mov    %rcx,0x8(%rdx)
  40e7c6:	jmpq   40e052 <TIFFGetField1+0x484>
  40e7cb:	mov    0x8(%rdx),%rcx
  40e7cf:	lea    0x8(%rcx),%rax
  40e7d3:	mov    %rax,0x8(%rdx)
  40e7d7:	jmpq   40e075 <TIFFGetField1+0x4a7>
  40e7dc:	mov    0x8(%rdx),%rcx
  40e7e0:	lea    0x8(%rcx),%rax
  40e7e4:	mov    %rax,0x8(%rdx)
  40e7e8:	jmpq   40e098 <TIFFGetField1+0x4ca>
  40e7ed:	mov    (%rdx),%ecx
  40e7ef:	cmp    $0x2f,%ecx
  40e7f2:	ja     40e80e <TIFFGetField1+0xc40>
  40e7f4:	mov    %ecx,%eax
  40e7f6:	add    0x10(%rdx),%rax
  40e7fa:	add    $0x8,%ecx
  40e7fd:	mov    %ecx,(%rdx)
  40e7ff:	mov    (%rax),%rax
  40e802:	movzwl 0x52(%rdi),%edx
  40e806:	mov    %dx,(%rax)
  40e809:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e80e:	mov    0x8(%rdx),%rax
  40e812:	lea    0x8(%rax),%rcx
  40e816:	mov    %rcx,0x8(%rdx)
  40e81a:	jmp    40e7ff <TIFFGetField1+0xc31>
  40e81c:	mov    (%rdx),%ecx
  40e81e:	cmp    $0x2f,%ecx
  40e821:	ja     40e840 <TIFFGetField1+0xc72>
  40e823:	mov    %ecx,%eax
  40e825:	add    0x10(%rdx),%rax
  40e829:	add    $0x8,%ecx
  40e82c:	mov    %ecx,(%rdx)
  40e82e:	mov    (%rax),%rax
  40e831:	mov    0x128(%rdi),%rdx
  40e838:	mov    %rdx,(%rax)
  40e83b:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e840:	mov    0x8(%rdx),%rax
  40e844:	lea    0x8(%rax),%rcx
  40e848:	mov    %rcx,0x8(%rdx)
  40e84c:	jmp    40e82e <TIFFGetField1+0xc60>
  40e84e:	mov    (%rdx),%ecx
  40e850:	cmp    $0x2f,%ecx
  40e853:	ja     40e872 <TIFFGetField1+0xca4>
  40e855:	mov    %ecx,%eax
  40e857:	add    0x10(%rdx),%rax
  40e85b:	add    $0x8,%ecx
  40e85e:	mov    %ecx,(%rdx)
  40e860:	mov    (%rax),%rax
  40e863:	mov    0x130(%rdi),%rdx
  40e86a:	mov    %rdx,(%rax)
  40e86d:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e872:	mov    0x8(%rdx),%rax
  40e876:	lea    0x8(%rax),%rcx
  40e87a:	mov    %rcx,0x8(%rdx)
  40e87e:	jmp    40e860 <TIFFGetField1+0xc92>
  40e880:	mov    0x8(%rdx),%rax
  40e884:	lea    0x8(%rax),%rcx
  40e888:	mov    %rcx,0x8(%rdx)
  40e88c:	jmpq   40e264 <TIFFGetField1+0x696>
  40e891:	mov    (%rdx),%ecx
  40e893:	cmp    $0x2f,%ecx
  40e896:	ja     40e8d4 <TIFFGetField1+0xd06>
  40e898:	mov    %ecx,%eax
  40e89a:	add    0x10(%rdx),%rax
  40e89e:	add    $0x8,%ecx
  40e8a1:	mov    %ecx,(%rdx)
  40e8a3:	mov    (%rax),%rax
  40e8a6:	movzwl 0x9c(%rdi),%ecx
  40e8ad:	mov    %cx,(%rax)
  40e8b0:	mov    (%rdx),%eax
  40e8b2:	cmp    $0x2f,%eax
  40e8b5:	ja     40e8e2 <TIFFGetField1+0xd14>
  40e8b7:	mov    %eax,%ecx
  40e8b9:	add    0x10(%rdx),%rcx
  40e8bd:	add    $0x8,%eax
  40e8c0:	mov    %eax,(%rdx)
  40e8c2:	mov    (%rcx),%rax
  40e8c5:	add    $0x9c,%rdi
  40e8cc:	mov    %rdi,(%rax)
  40e8cf:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e8d4:	mov    0x8(%rdx),%rax
  40e8d8:	lea    0x8(%rax),%rcx
  40e8dc:	mov    %rcx,0x8(%rdx)
  40e8e0:	jmp    40e8a3 <TIFFGetField1+0xcd5>
  40e8e2:	mov    0x8(%rdx),%rcx
  40e8e6:	lea    0x8(%rcx),%rax
  40e8ea:	mov    %rax,0x8(%rdx)
  40e8ee:	jmp    40e8c2 <TIFFGetField1+0xcf4>
  40e8f0:	mov    0x8(%rdx),%rax
  40e8f4:	lea    0x8(%rax),%rcx
  40e8f8:	mov    %rcx,0x8(%rdx)
  40e8fc:	jmpq   40e13b <TIFFGetField1+0x56d>
  40e901:	mov    (%rdx),%ecx
  40e903:	cmp    $0x2f,%ecx
  40e906:	ja     40e925 <TIFFGetField1+0xd57>
  40e908:	mov    %ecx,%eax
  40e90a:	add    0x10(%rdx),%rax
  40e90e:	add    $0x8,%ecx
  40e911:	mov    %ecx,(%rdx)
  40e913:	mov    (%rax),%rax
  40e916:	movzwl 0x9e(%rdi),%edx
  40e91d:	mov    %dx,(%rax)
  40e920:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e925:	mov    0x8(%rdx),%rax
  40e929:	lea    0x8(%rax),%rcx
  40e92d:	mov    %rcx,0x8(%rdx)
  40e931:	jmp    40e913 <TIFFGetField1+0xd45>
  40e933:	mov    0x8(%rdx),%rsi
  40e937:	lea    0x8(%rsi),%rcx
  40e93b:	mov    %rcx,0x8(%rdx)
  40e93f:	jmpq   40e0ff <TIFFGetField1+0x531>
  40e944:	mov    (%rdx),%ecx
  40e946:	cmp    $0x2f,%ecx
  40e949:	ja     40e965 <TIFFGetField1+0xd97>
  40e94b:	mov    %ecx,%eax
  40e94d:	add    0x10(%rdx),%rax
  40e951:	add    $0x8,%ecx
  40e954:	mov    %ecx,(%rdx)
  40e956:	mov    (%rax),%rax
  40e959:	mov    0x28(%rdi),%rdx
  40e95d:	mov    %rdx,(%rax)
  40e960:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e965:	mov    0x8(%rdx),%rax
  40e969:	lea    0x8(%rax),%rcx
  40e96d:	mov    %rcx,0x8(%rdx)
  40e971:	jmp    40e956 <TIFFGetField1+0xd88>
  40e973:	mov    (%rdx),%ecx
  40e975:	cmp    $0x2f,%ecx
  40e978:	ja     40e994 <TIFFGetField1+0xdc6>
  40e97a:	mov    %ecx,%eax
  40e97c:	add    0x10(%rdx),%rax
  40e980:	add    $0x8,%ecx
  40e983:	mov    %ecx,(%rdx)
  40e985:	mov    (%rax),%rax
  40e988:	mov    0x30(%rdi),%rdx
  40e98c:	mov    %rdx,(%rax)
  40e98f:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e994:	mov    0x8(%rdx),%rax
  40e998:	lea    0x8(%rax),%rcx
  40e99c:	mov    %rcx,0x8(%rdx)
  40e9a0:	jmp    40e985 <TIFFGetField1+0xdb7>
  40e9a2:	mov    0x8(%rdx),%rax
  40e9a6:	lea    0x8(%rax),%rcx
  40e9aa:	mov    %rcx,0x8(%rdx)
  40e9ae:	jmpq   40dfa9 <TIFFGetField1+0x3db>
  40e9b3:	movzwl 0x44(%rdi),%eax
  40e9b7:	cmp    $0x4,%ax
  40e9bb:	mov    $0x0,%ecx
  40e9c0:	cmove  %ecx,%eax
  40e9c3:	mov    (%rdx),%ecx
  40e9c5:	cmp    $0x2f,%ecx
  40e9c8:	ja     40e9e0 <TIFFGetField1+0xe12>
  40e9ca:	mov    %ecx,%esi
  40e9cc:	add    0x10(%rdx),%rsi
  40e9d0:	add    $0x8,%ecx
  40e9d3:	mov    %ecx,(%rdx)
  40e9d5:	mov    (%rsi),%rdx
  40e9d8:	mov    %ax,(%rdx)
  40e9db:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40e9e0:	mov    0x8(%rdx),%rsi
  40e9e4:	lea    0x8(%rsi),%rcx
  40e9e8:	mov    %rcx,0x8(%rdx)
  40e9ec:	jmp    40e9d5 <TIFFGetField1+0xe07>
  40e9ee:	mov    0x8(%rdx),%rax
  40e9f2:	lea    0x8(%rax),%rcx
  40e9f6:	mov    %rcx,0x8(%rdx)
  40e9fa:	jmpq   40e19b <TIFFGetField1+0x5cd>
  40e9ff:	mov    (%rdx),%ecx
  40ea01:	cmp    $0x2f,%ecx
  40ea04:	ja     40ea20 <TIFFGetField1+0xe52>
  40ea06:	mov    %ecx,%eax
  40ea08:	add    0x10(%rdx),%rax
  40ea0c:	add    $0x8,%ecx
  40ea0f:	mov    %ecx,(%rdx)
  40ea11:	mov    (%rax),%rax
  40ea14:	mov    0x20(%rdi),%rdx
  40ea18:	mov    %rdx,(%rax)
  40ea1b:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40ea20:	mov    0x8(%rdx),%rax
  40ea24:	lea    0x8(%rax),%rcx
  40ea28:	mov    %rcx,0x8(%rdx)
  40ea2c:	jmp    40ea11 <TIFFGetField1+0xe43>
  40ea2e:	mov    0x8(%rdx),%rax
  40ea32:	lea    0x8(%rax),%rcx
  40ea36:	mov    %rcx,0x8(%rdx)
  40ea3a:	jmpq   40e230 <TIFFGetField1+0x662>
  40ea3f:	mov    (%rdx),%ecx
  40ea41:	cmp    $0x2f,%ecx
  40ea44:	ja     40ea63 <TIFFGetField1+0xe95>
  40ea46:	mov    %ecx,%eax
  40ea48:	add    0x10(%rdx),%rax
  40ea4c:	add    $0x8,%ecx
  40ea4f:	mov    %ecx,(%rdx)
  40ea51:	mov    (%rax),%rax
  40ea54:	movzwl 0x144(%rdi),%edx
  40ea5b:	mov    %dx,(%rax)
  40ea5e:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40ea63:	mov    0x8(%rdx),%rax
  40ea67:	lea    0x8(%rax),%rcx
  40ea6b:	mov    %rcx,0x8(%rdx)
  40ea6f:	jmp    40ea51 <TIFFGetField1+0xe83>
  40ea71:	mov    (%rdx),%ecx
  40ea73:	cmp    $0x2f,%ecx
  40ea76:	ja     40eab4 <TIFFGetField1+0xee6>
  40ea78:	mov    %ecx,%eax
  40ea7a:	add    0x10(%rdx),%rax
  40ea7e:	add    $0x8,%ecx
  40ea81:	mov    %ecx,(%rdx)
  40ea83:	mov    (%rax),%rax
  40ea86:	movzwl 0x140(%rdi),%ecx
  40ea8d:	mov    %cx,(%rax)
  40ea90:	mov    (%rdx),%eax
  40ea92:	cmp    $0x2f,%eax
  40ea95:	ja     40eac2 <TIFFGetField1+0xef4>
  40ea97:	mov    %eax,%ecx
  40ea99:	add    0x10(%rdx),%rcx
  40ea9d:	add    $0x8,%eax
  40eaa0:	mov    %eax,(%rdx)
  40eaa2:	mov    (%rcx),%rax
  40eaa5:	movzwl 0x142(%rdi),%edx
  40eaac:	mov    %dx,(%rax)
  40eaaf:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40eab4:	mov    0x8(%rdx),%rax
  40eab8:	lea    0x8(%rax),%rcx
  40eabc:	mov    %rcx,0x8(%rdx)
  40eac0:	jmp    40ea83 <TIFFGetField1+0xeb5>
  40eac2:	mov    0x8(%rdx),%rcx
  40eac6:	lea    0x8(%rcx),%rax
  40eaca:	mov    %rax,0x8(%rdx)
  40eace:	jmp    40eaa2 <TIFFGetField1+0xed4>
  40ead0:	mov    (%rdx),%ecx
  40ead2:	cmp    $0x2f,%ecx
  40ead5:	ja     40eaf4 <TIFFGetField1+0xf26>
  40ead7:	mov    %ecx,%eax
  40ead9:	add    0x10(%rdx),%rax
  40eadd:	add    $0x8,%ecx
  40eae0:	mov    %ecx,(%rdx)
  40eae2:	mov    (%rax),%rax
  40eae5:	movzwl 0x146(%rdi),%edx
  40eaec:	mov    %dx,(%rax)
  40eaef:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40eaf4:	mov    0x8(%rdx),%rax
  40eaf8:	lea    0x8(%rax),%rcx
  40eafc:	mov    %rcx,0x8(%rdx)
  40eb00:	jmp    40eae2 <TIFFGetField1+0xf14>
  40eb02:	mov    0x8(%rdx),%rax
  40eb06:	lea    0x8(%rax),%rcx
  40eb0a:	mov    %rcx,0x8(%rdx)
  40eb0e:	jmpq   40e1e4 <TIFFGetField1+0x616>
  40eb13:	mov    (%rdx),%ecx
  40eb15:	cmp    $0x2f,%ecx
  40eb18:	ja     40eb37 <TIFFGetField1+0xf69>
  40eb1a:	mov    %ecx,%eax
  40eb1c:	add    0x10(%rdx),%rax
  40eb20:	add    $0x8,%ecx
  40eb23:	mov    %ecx,(%rdx)
  40eb25:	mov    (%rax),%rax
  40eb28:	mov    0x150(%rdi),%rdx
  40eb2f:	mov    %rdx,(%rax)
  40eb32:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40eb37:	mov    0x8(%rdx),%rax
  40eb3b:	lea    0x8(%rax),%rcx
  40eb3f:	mov    %rcx,0x8(%rdx)
  40eb43:	jmp    40eb25 <TIFFGetField1+0xf57>
  40eb45:	mov    (%rdx),%ecx
  40eb47:	cmp    $0x2f,%ecx
  40eb4a:	ja     40eb69 <TIFFGetField1+0xf9b>
  40eb4c:	mov    %ecx,%eax
  40eb4e:	add    0x10(%rdx),%rax
  40eb52:	add    $0x8,%ecx
  40eb55:	mov    %ecx,(%rdx)
  40eb57:	mov    (%rax),%rax
  40eb5a:	mov    0x158(%rdi),%rdx
  40eb61:	mov    %rdx,(%rax)
  40eb64:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40eb69:	mov    0x8(%rdx),%rax
  40eb6d:	lea    0x8(%rax),%rcx
  40eb71:	mov    %rcx,0x8(%rdx)
  40eb75:	jmp    40eb57 <TIFFGetField1+0xf89>
  40eb77:	mov    (%rdx),%ecx
  40eb79:	cmp    $0x2f,%ecx
  40eb7c:	ja     40eb9b <TIFFGetField1+0xfcd>
  40eb7e:	mov    %ecx,%eax
  40eb80:	add    0x10(%rdx),%rax
  40eb84:	add    $0x8,%ecx
  40eb87:	mov    %ecx,(%rdx)
  40eb89:	mov    (%rax),%rax
  40eb8c:	mov    0x160(%rdi),%rdx
  40eb93:	mov    %rdx,(%rax)
  40eb96:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40eb9b:	mov    0x8(%rdx),%rax
  40eb9f:	lea    0x8(%rax),%rcx
  40eba3:	mov    %rcx,0x8(%rdx)
  40eba7:	jmp    40eb89 <TIFFGetField1+0xfbb>
  40eba9:	mov    (%rdx),%ecx
  40ebab:	cmp    $0x2f,%ecx
  40ebae:	ja     40ebcd <TIFFGetField1+0xfff>
  40ebb0:	mov    %ecx,%eax
  40ebb2:	add    0x10(%rdx),%rax
  40ebb6:	add    $0x8,%ecx
  40ebb9:	mov    %ecx,(%rdx)
  40ebbb:	mov    (%rax),%rax
  40ebbe:	mov    0x168(%rdi),%rdx
  40ebc5:	mov    %rdx,(%rax)
  40ebc8:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40ebcd:	mov    0x8(%rdx),%rax
  40ebd1:	lea    0x8(%rax),%rcx
  40ebd5:	mov    %rcx,0x8(%rdx)
  40ebd9:	jmp    40ebbb <TIFFGetField1+0xfed>
  40ebdb:	mov    (%rdx),%ecx
  40ebdd:	cmp    $0x2f,%ecx
  40ebe0:	ja     40ebff <TIFFGetField1+0x1031>
  40ebe2:	mov    %ecx,%eax
  40ebe4:	add    0x10(%rdx),%rax
  40ebe8:	add    $0x8,%ecx
  40ebeb:	mov    %ecx,(%rdx)
  40ebed:	mov    (%rax),%rax
  40ebf0:	mov    0x170(%rdi),%rdx
  40ebf7:	mov    %rdx,(%rax)
  40ebfa:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40ebff:	mov    0x8(%rdx),%rax
  40ec03:	lea    0x8(%rax),%rcx
  40ec07:	mov    %rcx,0x8(%rdx)
  40ec0b:	jmp    40ebed <TIFFGetField1+0x101f>
  40ec0d:	mov    0x8(%rdx),%rcx
  40ec11:	lea    0x8(%rcx),%rsi
  40ec15:	mov    %rsi,0x8(%rdx)
  40ec19:	mov    (%rcx),%rcx
  40ec1c:	mov    0x178(%rdi,%rax,8),%rsi
  40ec24:	mov    %rsi,(%rcx)
  40ec27:	mov    %eax,%ecx
  40ec29:	add    $0x1,%rax
  40ec2d:	movzwl 0x50(%rdi),%esi
  40ec31:	cmp    %ecx,%esi
  40ec33:	jle    40dcf2 <TIFFGetField1+0x124>
  40ec39:	mov    (%rdx),%esi
  40ec3b:	cmp    $0x2f,%esi
  40ec3e:	ja     40ec0d <TIFFGetField1+0x103f>
  40ec40:	mov    %esi,%ecx
  40ec42:	add    0x10(%rdx),%rcx
  40ec46:	add    $0x8,%esi
  40ec49:	mov    %esi,(%rdx)
  40ec4b:	jmp    40ec19 <TIFFGetField1+0x104b>
  40ec4d:	mov    (%rdx),%ecx
  40ec4f:	cmp    $0x2f,%ecx
  40ec52:	ja     40ec71 <TIFFGetField1+0x10a3>
  40ec54:	mov    %ecx,%eax
  40ec56:	add    0x10(%rdx),%rax
  40ec5a:	add    $0x8,%ecx
  40ec5d:	mov    %ecx,(%rdx)
  40ec5f:	mov    (%rax),%rax
  40ec62:	mov    0x178(%rdi),%rdx
  40ec69:	mov    %rdx,(%rax)
  40ec6c:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40ec71:	mov    0x8(%rdx),%rax
  40ec75:	lea    0x8(%rax),%rcx
  40ec79:	mov    %rcx,0x8(%rdx)
  40ec7d:	jmp    40ec5f <TIFFGetField1+0x1091>
  40ec7f:	mov    (%rdx),%ecx
  40ec81:	cmp    $0x2f,%ecx
  40ec84:	ja     40eca3 <TIFFGetField1+0x10d5>
  40ec86:	mov    %ecx,%eax
  40ec88:	add    0x10(%rdx),%rax
  40ec8c:	add    $0x8,%ecx
  40ec8f:	mov    %ecx,(%rdx)
  40ec91:	mov    (%rax),%rax
  40ec94:	movzwl 0x1a0(%rdi),%edx
  40ec9b:	mov    %dx,(%rax)
  40ec9e:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40eca3:	mov    0x8(%rdx),%rax
  40eca7:	lea    0x8(%rax),%rcx
  40ecab:	mov    %rcx,0x8(%rdx)
  40ecaf:	jmp    40ec91 <TIFFGetField1+0x10c3>
  40ecb1:	mov    (%rdx),%ecx
  40ecb3:	cmp    $0x2f,%ecx
  40ecb6:	ja     40ecf4 <TIFFGetField1+0x1126>
  40ecb8:	mov    %ecx,%eax
  40ecba:	add    0x10(%rdx),%rax
  40ecbe:	add    $0x8,%ecx
  40ecc1:	mov    %ecx,(%rdx)
  40ecc3:	mov    (%rax),%rax
  40ecc6:	movzwl 0x1a2(%rdi),%ecx
  40eccd:	mov    %cx,(%rax)
  40ecd0:	mov    (%rdx),%eax
  40ecd2:	cmp    $0x2f,%eax
  40ecd5:	ja     40ed02 <TIFFGetField1+0x1134>
  40ecd7:	mov    %eax,%ecx
  40ecd9:	add    0x10(%rdx),%rcx
  40ecdd:	add    $0x8,%eax
  40ece0:	mov    %eax,(%rdx)
  40ece2:	mov    (%rcx),%rax
  40ece5:	movzwl 0x1a4(%rdi),%edx
  40ecec:	mov    %dx,(%rax)
  40ecef:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40ecf4:	mov    0x8(%rdx),%rax
  40ecf8:	lea    0x8(%rax),%rcx
  40ecfc:	mov    %rcx,0x8(%rdx)
  40ed00:	jmp    40ecc3 <TIFFGetField1+0x10f5>
  40ed02:	mov    0x8(%rdx),%rcx
  40ed06:	lea    0x8(%rcx),%rax
  40ed0a:	mov    %rax,0x8(%rdx)
  40ed0e:	jmp    40ece2 <TIFFGetField1+0x1114>
  40ed10:	mov    (%rdx),%ecx
  40ed12:	cmp    $0x2f,%ecx
  40ed15:	ja     40ed34 <TIFFGetField1+0x1166>
  40ed17:	mov    %ecx,%eax
  40ed19:	add    0x10(%rdx),%rax
  40ed1d:	add    $0x8,%ecx
  40ed20:	mov    %ecx,(%rdx)
  40ed22:	mov    (%rax),%rax
  40ed25:	mov    0x1a8(%rdi),%rdx
  40ed2c:	mov    %rdx,(%rax)
  40ed2f:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40ed34:	mov    0x8(%rdx),%rax
  40ed38:	lea    0x8(%rax),%rcx
  40ed3c:	mov    %rcx,0x8(%rdx)
  40ed40:	jmp    40ed22 <TIFFGetField1+0x1154>
  40ed42:	mov    (%rdx),%ecx
  40ed44:	cmp    $0x2f,%ecx
  40ed47:	ja     40ed66 <TIFFGetField1+0x1198>
  40ed49:	mov    %ecx,%eax
  40ed4b:	add    0x10(%rdx),%rax
  40ed4f:	add    $0x8,%ecx
  40ed52:	mov    %ecx,(%rdx)
  40ed54:	mov    (%rax),%rax
  40ed57:	mov    0x1b0(%rdi),%rdx
  40ed5e:	mov    %rdx,(%rax)
  40ed61:	jmpq   40dcf2 <TIFFGetField1+0x124>
  40ed66:	mov    0x8(%rdx),%rax
  40ed6a:	lea    0x8(%rax),%rcx
  40ed6e:	mov    %rcx,0x8(%rdx)
  40ed72:	jmp    40ed54 <TIFFGetField1+0x1186>

000000000040ed74 <setJPEGCTable>:
  40ed74:	push   %r15
  40ed76:	push   %r14
  40ed78:	push   %r13
  40ed7a:	push   %r12
  40ed7c:	push   %rbp
  40ed7d:	push   %rbx
  40ed7e:	sub    $0x8,%rsp
  40ed82:	mov    %rdi,%r13
  40ed85:	mov    %rsi,%r14
  40ed88:	mov    %edx,%ebp
  40ed8a:	mov    (%rdi),%rdi
  40ed8d:	test   %rdi,%rdi
  40ed90:	je     40ed9f <setJPEGCTable+0x2b>
  40ed92:	callq  4010b0 <free@plt>
  40ed97:	movq   $0x0,0x0(%r13)
  40ed9f:	test   %ebp,%ebp
  40eda1:	jle    40ee5d <setJPEGCTable+0xe9>
  40eda7:	mov    %r14,%rdi
  40edaa:	lea    -0x1(%rbp),%ebx
  40edad:	lea    0x8(%r14,%rbx,8),%r8
  40edb2:	mov    $0x0,%edx
  40edb7:	add    $0x10,%edx
  40edba:	mov    (%rdi),%rax
  40edbd:	lea    0x10(%rax),%rsi
  40edc1:	movzbl (%rax),%ecx
  40edc4:	add    %ecx,%edx
  40edc6:	add    $0x1,%rax
  40edca:	cmp    %rsi,%rax
  40edcd:	jne    40edc1 <setJPEGCTable+0x4d>
  40edcf:	add    $0x8,%rdi
  40edd3:	cmp    %r8,%rdi
  40edd6:	jne    40edb7 <setJPEGCTable+0x43>
  40edd8:	movslq %ebp,%rbp
  40eddb:	shl    $0x3,%rbp
  40eddf:	movslq %edx,%rdx
  40ede2:	lea    (%rdx,%rbp,1),%rdi
  40ede6:	mov    $0x0,%eax
  40edeb:	callq  401270 <malloc@plt>
  40edf0:	mov    %rax,0x0(%r13)
  40edf4:	lea    (%rax,%rbp,1),%r12
  40edf8:	lea    0x8(,%rbx,8),%r15
  40ee00:	mov    $0x0,%ebp
  40ee05:	mov    0x0(%r13),%rax
  40ee09:	mov    %r12,(%rax,%rbp,1)
  40ee0d:	mov    (%r14,%rbp,1),%rdi
  40ee11:	mov    %rdi,%rax
  40ee14:	lea    0x10(%rdi),%rcx
  40ee18:	mov    $0x10,%ebx
  40ee1d:	movzbl (%rax),%edx
  40ee20:	add    %edx,%ebx
  40ee22:	add    $0x1,%rax
  40ee26:	cmp    %rax,%rcx
  40ee29:	jne    40ee1d <setJPEGCTable+0xa9>
  40ee2b:	mov    %ebx,%edx
  40ee2d:	mov    %r12,%rsi
  40ee30:	mov    $0x0,%eax
  40ee35:	callq  4012d0 <bcopy@plt>
  40ee3a:	movslq %ebx,%rbx
  40ee3d:	add    %rbx,%r12
  40ee40:	add    $0x8,%rbp
  40ee44:	cmp    %r15,%rbp
  40ee47:	jne    40ee05 <setJPEGCTable+0x91>
  40ee49:	mov    $0x0,%eax
  40ee4e:	add    $0x8,%rsp
  40ee52:	pop    %rbx
  40ee53:	pop    %rbp
  40ee54:	pop    %r12
  40ee56:	pop    %r13
  40ee58:	pop    %r14
  40ee5a:	pop    %r15
  40ee5c:	retq   
  40ee5d:	movslq %ebp,%rdi
  40ee60:	shl    $0x3,%rdi
  40ee64:	mov    $0x0,%eax
  40ee69:	callq  401270 <malloc@plt>
  40ee6e:	mov    %rax,0x0(%r13)
  40ee72:	jmp    40ee49 <setJPEGCTable+0xd5>

000000000040ee74 <setShortArray>:
  40ee74:	push   %r12
  40ee76:	push   %rbp
  40ee77:	push   %rbx
  40ee78:	mov    %rdi,%rbx
  40ee7b:	mov    %rsi,%r12
  40ee7e:	mov    %rdx,%rbp
  40ee81:	mov    (%rdi),%rdi
  40ee84:	test   %rdi,%rdi
  40ee87:	je     40ee95 <setShortArray+0x21>
  40ee89:	callq  4010b0 <free@plt>
  40ee8e:	movq   $0x0,(%rbx)
  40ee95:	test   %r12,%r12
  40ee98:	je     40eec5 <setShortArray+0x51>
  40ee9a:	add    %rbp,%rbp
  40ee9d:	mov    %rbp,%rdi
  40eea0:	mov    $0x0,%eax
  40eea5:	callq  401270 <malloc@plt>
  40eeaa:	mov    %rax,(%rbx)
  40eead:	test   %rax,%rax
  40eeb0:	je     40eec5 <setShortArray+0x51>
  40eeb2:	mov    %rbp,%rdx
  40eeb5:	mov    %rax,%rsi
  40eeb8:	mov    %r12,%rdi
  40eebb:	mov    $0x0,%eax
  40eec0:	callq  4012d0 <bcopy@plt>
  40eec5:	pop    %rbx
  40eec6:	pop    %rbp
  40eec7:	pop    %r12
  40eec9:	retq   

000000000040eeca <setFloatArray>:
  40eeca:	push   %r12
  40eecc:	push   %rbp
  40eecd:	push   %rbx
  40eece:	mov    %rdi,%rbx
  40eed1:	mov    %rsi,%r12
  40eed4:	mov    %rdx,%rbp
  40eed7:	mov    (%rdi),%rdi
  40eeda:	test   %rdi,%rdi
  40eedd:	je     40eeeb <setFloatArray+0x21>
  40eedf:	callq  4010b0 <free@plt>
  40eee4:	movq   $0x0,(%rbx)
  40eeeb:	test   %r12,%r12
  40eeee:	je     40ef1c <setFloatArray+0x52>
  40eef0:	shl    $0x2,%rbp
  40eef4:	mov    %rbp,%rdi
  40eef7:	mov    $0x0,%eax
  40eefc:	callq  401270 <malloc@plt>
  40ef01:	mov    %rax,(%rbx)
  40ef04:	test   %rax,%rax
  40ef07:	je     40ef1c <setFloatArray+0x52>
  40ef09:	mov    %rbp,%rdx
  40ef0c:	mov    %rax,%rsi
  40ef0f:	mov    %r12,%rdi
  40ef12:	mov    $0x0,%eax
  40ef17:	callq  4012d0 <bcopy@plt>
  40ef1c:	pop    %rbx
  40ef1d:	pop    %rbp
  40ef1e:	pop    %r12
  40ef20:	retq   

000000000040ef21 <setString>:
  40ef21:	push   %r12
  40ef23:	push   %rbp
  40ef24:	push   %rbx
  40ef25:	mov    %rdi,%rbp
  40ef28:	mov    %rsi,%r12
  40ef2b:	mov    (%rdi),%rdi
  40ef2e:	test   %rdi,%rdi
  40ef31:	je     40ef40 <setString+0x1f>
  40ef33:	callq  4010b0 <free@plt>
  40ef38:	movq   $0x0,0x0(%rbp)
  40ef40:	test   %r12,%r12
  40ef43:	je     40ef7c <setString+0x5b>
  40ef45:	mov    $0xffffffffffffffff,%rcx
  40ef4c:	mov    $0x0,%eax
  40ef51:	mov    %r12,%rdi
  40ef54:	repnz scas %es:(%rdi),%al
  40ef56:	mov    %ecx,%ebx
  40ef58:	not    %ebx
  40ef5a:	mov    %ebx,%edi
  40ef5c:	callq  401270 <malloc@plt>
  40ef61:	mov    %rax,0x0(%rbp)
  40ef65:	test   %rax,%rax
  40ef68:	je     40ef7c <setString+0x5b>
  40ef6a:	mov    %ebx,%edx
  40ef6c:	mov    %rax,%rsi
  40ef6f:	mov    %r12,%rdi
  40ef72:	mov    $0x0,%eax
  40ef77:	callq  4012d0 <bcopy@plt>
  40ef7c:	pop    %rbx
  40ef7d:	pop    %rbp
  40ef7e:	pop    %r12
  40ef80:	retq   

000000000040ef81 <TIFFSetField1>:
  40ef81:	push   %r14
  40ef83:	push   %r13
  40ef85:	push   %r12
  40ef87:	push   %rbp
  40ef88:	push   %rbx
  40ef89:	mov    %rdi,%rbp
  40ef8c:	mov    %esi,%ebx
  40ef8e:	mov    %rdx,%r12
  40ef91:	cmp    $0x13b,%esi
  40ef97:	je     40f8c9 <TIFFSetField1+0x948>
  40ef9d:	cmp    $0x13b,%esi
  40efa3:	jg     40f2db <TIFFSetField1+0x35a>
  40efa9:	cmp    $0x116,%esi
  40efaf:	je     40fb59 <TIFFSetField1+0xbd8>
  40efb5:	cmp    $0x116,%esi
  40efbb:	jle    40f043 <TIFFSetField1+0xc2>
  40efc1:	cmp    $0x11f,%esi
  40efc7:	je     40fd30 <TIFFSetField1+0xdaf>
  40efcd:	cmp    $0x11f,%esi
  40efd3:	jg     40f22f <TIFFSetField1+0x2ae>
  40efd9:	cmp    $0x11b,%esi
  40efdf:	je     40fc41 <TIFFSetField1+0xcc0>
  40efe5:	cmp    $0x11b,%esi
  40efeb:	jg     40f1e2 <TIFFSetField1+0x261>
  40eff1:	cmp    $0x119,%esi
  40eff7:	je     40fbc2 <TIFFSetField1+0xc41>
  40effd:	cmp    $0x119,%esi
  40f003:	jg     40fbfc <TIFFSetField1+0xc7b>
  40f009:	cmp    $0x118,%esi
  40f00f:	jne    40f1b8 <TIFFSetField1+0x237>
  40f015:	mov    (%rdx),%edx
  40f017:	cmp    $0x2f,%edx
  40f01a:	ja     40fbaf <TIFFSetField1+0xc2e>
  40f020:	mov    %edx,%eax
  40f022:	add    0x10(%r12),%rax
  40f027:	add    $0x8,%edx
  40f02a:	mov    %edx,(%r12)
  40f02e:	movzwl (%rax),%eax
  40f031:	mov    %rax,0x80(%rbp)
  40f038:	mov    $0x1,%r12d
  40f03e:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f043:	cmp    $0x107,%esi
  40f049:	je     40f832 <TIFFSetField1+0x8b1>
  40f04f:	cmp    $0x107,%esi
  40f055:	jle    40f0f3 <TIFFSetField1+0x172>
  40f05b:	cmp    $0x10f,%esi
  40f061:	je     40f9c5 <TIFFSetField1+0xa44>
  40f067:	cmp    $0x10f,%esi
  40f06d:	jg     40f194 <TIFFSetField1+0x213>
  40f073:	cmp    $0x10d,%esi
  40f079:	je     40f88a <TIFFSetField1+0x909>
  40f07f:	cmp    $0x10d,%esi
  40f085:	jg     40f986 <TIFFSetField1+0xa05>
  40f08b:	cmp    $0x10a,%esi
  40f091:	jne    40f1b8 <TIFFSetField1+0x237>
  40f097:	mov    (%rdx),%edx
  40f099:	cmp    $0x2f,%edx
  40f09c:	ja     40f868 <TIFFSetField1+0x8e7>
  40f0a2:	mov    %edx,%eax
  40f0a4:	add    0x10(%r12),%rax
  40f0a9:	add    $0x8,%edx
  40f0ac:	mov    %edx,(%r12)
  40f0b0:	mov    (%rax),%edx
  40f0b2:	movslq %edx,%rax
  40f0b5:	sub    $0x1,%rax
  40f0b9:	movslq %edx,%r13
  40f0bc:	cmp    $0x1,%rax
  40f0c0:	jbe    40f87b <TIFFSetField1+0x8fa>
  40f0c6:	movzwl %bx,%edi
  40f0c9:	callq  410ebe <TIFFFieldWithTag>
  40f0ce:	mov    0x10(%rax),%rcx
  40f0d2:	mov    %r13,%rdx
  40f0d5:	mov    $0x419af0,%esi
  40f0da:	mov    0x0(%rbp),%rdi
  40f0de:	mov    $0x0,%eax
  40f0e3:	callq  412a93 <TIFFError>
  40f0e8:	mov    $0x0,%r12d
  40f0ee:	jmpq   40f709 <TIFFSetField1+0x788>
  40f0f3:	cmp    $0x101,%esi
  40f0f9:	je     40f738 <TIFFSetField1+0x7b7>
  40f0ff:	cmp    $0x101,%esi
  40f105:	jle    40f155 <TIFFSetField1+0x1d4>
  40f107:	cmp    $0x103,%esi
  40f10d:	je     40f7a5 <TIFFSetField1+0x824>
  40f113:	cmp    $0x103,%esi
  40f119:	jl     40f76f <TIFFSetField1+0x7ee>
  40f11f:	cmp    $0x106,%esi
  40f125:	jne    40f1b8 <TIFFSetField1+0x237>
  40f12b:	mov    (%rdx),%edx
  40f12d:	cmp    $0x2f,%edx
  40f130:	ja     40f81f <TIFFSetField1+0x89e>
  40f136:	mov    %edx,%eax
  40f138:	add    0x10(%r12),%rax
  40f13d:	add    $0x8,%edx
  40f140:	mov    %edx,(%r12)
  40f144:	mov    (%rax),%eax
  40f146:	mov    %ax,0x68(%rbp)
  40f14a:	mov    $0x1,%r12d
  40f150:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f155:	cmp    $0xfe,%esi
  40f15b:	je     40f6b1 <TIFFSetField1+0x730>
  40f161:	cmp    $0x100,%esi
  40f167:	jne    40f1b8 <TIFFSetField1+0x237>
  40f169:	mov    (%rdx),%edx
  40f16b:	cmp    $0x2f,%edx
  40f16e:	ja     40f725 <TIFFSetField1+0x7a4>
  40f174:	mov    %edx,%eax
  40f176:	add    0x10(%r12),%rax
  40f17b:	add    $0x8,%edx
  40f17e:	mov    %edx,(%r12)
  40f182:	mov    (%rax),%rax
  40f185:	mov    %rax,0x30(%rbp)
  40f189:	mov    $0x1,%r12d
  40f18f:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f194:	cmp    $0x112,%esi
  40f19a:	je     40fa82 <TIFFSetField1+0xb01>
  40f1a0:	cmp    $0x115,%esi
  40f1a6:	je     40faf6 <TIFFSetField1+0xb75>
  40f1ac:	cmp    $0x110,%esi
  40f1b2:	je     40fa04 <TIFFSetField1+0xa83>
  40f1b8:	movzwl %bx,%edi
  40f1bb:	callq  410ebe <TIFFFieldWithTag>
  40f1c0:	mov    0x10(%rax),%rdx
  40f1c4:	mov    $0x419a38,%esi
  40f1c9:	mov    0x0(%rbp),%rdi
  40f1cd:	mov    $0x0,%eax
  40f1d2:	callq  412a93 <TIFFError>
  40f1d7:	mov    $0x0,%r12d
  40f1dd:	jmpq   40f709 <TIFFSetField1+0x788>
  40f1e2:	cmp    $0x11d,%esi
  40f1e8:	je     40fcac <TIFFSetField1+0xd2b>
  40f1ee:	cmp    $0x11d,%esi
  40f1f4:	jg     40fceb <TIFFSetField1+0xd6a>
  40f1fa:	mov    (%rdx),%edx
  40f1fc:	cmp    $0x2f,%edx
  40f1ff:	ja     40fc86 <TIFFSetField1+0xd05>
  40f205:	mov    %edx,%eax
  40f207:	add    0x10(%r12),%rax
  40f20c:	add    $0x8,%edx
  40f20f:	mov    %edx,(%r12)
  40f213:	mov    (%rax),%r13d
  40f216:	movslq %r13d,%rax
  40f219:	sub    $0x1,%rax
  40f21d:	cmp    $0x1,%rax
  40f221:	jbe    40fc99 <TIFFSetField1+0xd18>
  40f227:	movslq %r13d,%r13
  40f22a:	jmpq   40f0c6 <TIFFSetField1+0x145>
  40f22f:	cmp    $0x129,%esi
  40f235:	je     40fe12 <TIFFSetField1+0xe91>
  40f23b:	cmp    $0x129,%esi
  40f241:	jg     40f295 <TIFFSetField1+0x314>
  40f243:	cmp    $0x125,%esi
  40f249:	je     40fd88 <TIFFSetField1+0xe07>
  40f24f:	cmp    $0x128,%esi
  40f255:	je     40fdc2 <TIFFSetField1+0xe41>
  40f25b:	cmp    $0x124,%esi
  40f261:	jne    40f1b8 <TIFFSetField1+0x237>
  40f267:	mov    (%rdx),%edx
  40f269:	cmp    $0x2f,%edx
  40f26c:	ja     40fd75 <TIFFSetField1+0xdf4>
  40f272:	mov    %edx,%eax
  40f274:	add    0x10(%r12),%rax
  40f279:	add    $0x8,%edx
  40f27c:	mov    %edx,(%r12)
  40f280:	mov    (%rax),%rax
  40f283:	mov    %rax,0xa8(%rbp)
  40f28a:	mov    $0x1,%r12d
  40f290:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f295:	cmp    $0x131,%esi
  40f29b:	je     40fa43 <TIFFSetField1+0xac2>
  40f2a1:	cmp    $0x132,%esi
  40f2a7:	je     40f908 <TIFFSetField1+0x987>
  40f2ad:	cmp    $0x12d,%esi
  40f2b3:	jne    40f1b8 <TIFFSetField1+0x237>
  40f2b9:	mov    $0x0,%r13d
  40f2bf:	mov    $0x1,%r14d
  40f2c5:	cmpw   $0x0,0x70(%rdi)
  40f2ca:	jne    410478 <TIFFSetField1+0x14f7>
  40f2d0:	mov    $0x1,%r12d
  40f2d6:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f2db:	cmp    $0x151,%esi
  40f2e1:	je     410574 <TIFFSetField1+0x15f3>
  40f2e7:	cmp    $0x151,%esi
  40f2ed:	jg     40f475 <TIFFSetField1+0x4f4>
  40f2f3:	cmp    $0x142,%esi
  40f2f9:	je     410120 <TIFFSetField1+0x119f>
  40f2ff:	cmp    $0x142,%esi
  40f305:	jle    40f37e <TIFFSetField1+0x3fd>
  40f307:	cmp    $0x148,%esi
  40f30d:	je     4100e6 <TIFFSetField1+0x1165>
  40f313:	cmp    $0x148,%esi
  40f319:	jg     40f424 <TIFFSetField1+0x4a3>
  40f31f:	cmp    $0x146,%esi
  40f325:	je     410073 <TIFFSetField1+0x10f2>
  40f32b:	cmp    $0x146,%esi
  40f331:	jg     4100ad <TIFFSetField1+0x112c>
  40f337:	cmp    $0x143,%esi
  40f33d:	jne    40f1b8 <TIFFSetField1+0x237>
  40f343:	mov    (%rdx),%edx
  40f345:	cmp    $0x2f,%edx
  40f348:	ja     410167 <TIFFSetField1+0x11e6>
  40f34e:	mov    %edx,%eax
  40f350:	add    0x10(%r12),%rax
  40f355:	add    $0x8,%edx
  40f358:	mov    %edx,(%r12)
  40f35c:	mov    (%rax),%r13
  40f35f:	test   $0x7,%r13b
  40f363:	jne    40f0c6 <TIFFSetField1+0x145>
  40f369:	mov    %r13,0x50(%rbp)
  40f36d:	orw    $0x80,0xe(%rbp)
  40f373:	mov    $0x1,%r12d
  40f379:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f37e:	cmp    $0x13e,%esi
  40f384:	je     4103f3 <TIFFSetField1+0x1472>
  40f38a:	cmp    $0x13e,%esi
  40f390:	jle    40f3e2 <TIFFSetField1+0x461>
  40f392:	cmp    $0x140,%esi
  40f398:	je     40fee4 <TIFFSetField1+0xf63>
  40f39e:	cmp    $0x140,%esi
  40f3a4:	jg     40fe7b <TIFFSetField1+0xefa>
  40f3aa:	mov    (%rdx),%edx
  40f3ac:	cmp    $0x2f,%edx
  40f3af:	ja     410437 <TIFFSetField1+0x14b6>
  40f3b5:	mov    %edx,%eax
  40f3b7:	add    0x10(%r12),%rax
  40f3bc:	add    $0x8,%edx
  40f3bf:	mov    %edx,(%r12)
  40f3c3:	lea    0x190(%rbp),%rdi
  40f3ca:	mov    $0x6,%edx
  40f3cf:	mov    (%rax),%rsi
  40f3d2:	callq  40eeca <setFloatArray>
  40f3d7:	mov    $0x1,%r12d
  40f3dd:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f3e2:	cmp    $0x13c,%esi
  40f3e8:	je     40f947 <TIFFSetField1+0x9c6>
  40f3ee:	cmp    $0x13d,%esi
  40f3f4:	jne    40f1b8 <TIFFSetField1+0x237>
  40f3fa:	mov    (%rdx),%edx
  40f3fc:	cmp    $0x2f,%edx
  40f3ff:	ja     40ffa0 <TIFFSetField1+0x101f>
  40f405:	mov    %edx,%eax
  40f407:	add    0x10(%r12),%rax
  40f40c:	add    $0x8,%edx
  40f40f:	mov    %edx,(%r12)
  40f413:	mov    (%rax),%eax
  40f415:	mov    %ax,0x72(%rbp)
  40f419:	mov    $0x1,%r12d
  40f41f:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f424:	cmp    $0x14d,%esi
  40f42a:	je     410535 <TIFFSetField1+0x15b4>
  40f430:	cmp    $0x150,%esi
  40f436:	je     4104cc <TIFFSetField1+0x154b>
  40f43c:	cmp    $0x14c,%esi
  40f442:	jne    40f1b8 <TIFFSetField1+0x237>
  40f448:	mov    (%rdx),%edx
  40f44a:	cmp    $0x2f,%edx
  40f44d:	ja     4104b9 <TIFFSetField1+0x1538>
  40f453:	mov    %edx,%eax
  40f455:	add    0x10(%r12),%rax
  40f45a:	add    $0x8,%edx
  40f45d:	mov    %edx,(%r12)
  40f461:	mov    (%rax),%eax
  40f463:	mov    %ax,0x1c0(%rbp)
  40f46a:	mov    $0x1,%r12d
  40f470:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f475:	cmp    $0x211,%esi
  40f47b:	je     410225 <TIFFSetField1+0x12a4>
  40f481:	cmp    $0x211,%esi
  40f487:	jg     40f5e9 <TIFFSetField1+0x668>
  40f48d:	cmp    $0x203,%esi
  40f493:	je     41031e <TIFFSetField1+0x139d>
  40f499:	cmp    $0x203,%esi
  40f49f:	jle    40f598 <TIFFSetField1+0x617>
  40f4a5:	cmp    $0x208,%esi
  40f4ab:	je     410369 <TIFFSetField1+0x13e8>
  40f4b1:	cmp    $0x209,%esi
  40f4b7:	je     4103ae <TIFFSetField1+0x142d>
  40f4bd:	cmp    $0x207,%esi
  40f4c3:	jne    40f1b8 <TIFFSetField1+0x237>
  40f4c9:	movzwl 0x70(%rdi),%r13d
  40f4ce:	mov    (%rdx),%eax
  40f4d0:	cmp    $0x2f,%eax
  40f4d3:	ja     410357 <TIFFSetField1+0x13d6>
  40f4d9:	mov    %eax,%edx
  40f4db:	add    0x10(%r12),%rdx
  40f4e0:	add    $0x8,%eax
  40f4e3:	mov    %eax,(%r12)
  40f4e7:	mov    (%rdx),%r12
  40f4ea:	mov    0x170(%rbp),%rdi
  40f4f1:	test   %rdi,%rdi
  40f4f4:	je     40f506 <TIFFSetField1+0x585>
  40f4f6:	callq  4010b0 <free@plt>
  40f4fb:	movq   $0x0,0x170(%rbp)
  40f506:	movzwl %r13w,%eax
  40f50a:	lea    0x0(,%rax,8),%r14
  40f512:	add    %r14,%rax
  40f515:	lea    0x0(,%rax,8),%rdi
  40f51d:	mov    $0x0,%eax
  40f522:	callq  401270 <malloc@plt>
  40f527:	mov    %rax,0x170(%rbp)
  40f52e:	lea    (%rax,%r14,1),%rdi
  40f532:	test   %r13w,%r13w
  40f536:	je     4105be <TIFFSetField1+0x163d>
  40f53c:	mov    %r12,%r9
  40f53f:	movzwl %r13w,%r13d
  40f543:	lea    -0x1(%r13),%eax
  40f547:	lea    0x8(%r12,%rax,8),%r8
  40f54c:	mov    %r12,%rsi
  40f54f:	mov    %rsi,%rax
  40f552:	sub    %r9,%rax
  40f555:	mov    0x170(%rbp),%rdx
  40f55c:	mov    %rdi,(%rdx,%rax,1)
  40f560:	mov    $0x0,%eax
  40f565:	movzbl 0x419b60(%rax),%edx
  40f56c:	mov    (%rsi),%rcx
  40f56f:	movzbl (%rcx,%rax,1),%ecx
  40f573:	mov    %cl,(%rdi,%rdx,1)
  40f576:	add    $0x1,%rax
  40f57a:	cmp    $0x40,%rax
  40f57e:	jne    40f565 <TIFFSetField1+0x5e4>
  40f580:	add    $0x40,%rdi
  40f584:	add    $0x8,%rsi
  40f588:	cmp    %rsi,%r8
  40f58b:	jne    40f54f <TIFFSetField1+0x5ce>
  40f58d:	mov    $0x1,%r12d
  40f593:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f598:	cmp    $0x153,%esi
  40f59e:	je     41018d <TIFFSetField1+0x120c>
  40f5a4:	cmp    $0x153,%esi
  40f5aa:	jl     40ffb3 <TIFFSetField1+0x1032>
  40f5b0:	cmp    $0x200,%esi
  40f5b6:	jne    40f1b8 <TIFFSetField1+0x237>
  40f5bc:	mov    (%rdx),%edx
  40f5be:	cmp    $0x2f,%edx
  40f5c1:	ja     41030b <TIFFSetField1+0x138a>
  40f5c7:	mov    %edx,%eax
  40f5c9:	add    0x10(%r12),%rax
  40f5ce:	add    $0x8,%edx
  40f5d1:	mov    %edx,(%r12)
  40f5d5:	mov    (%rax),%eax
  40f5d7:	mov    %ax,0x166(%rbp)
  40f5de:	mov    $0x1,%r12d
  40f5e4:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f5e9:	cmp    $0x80e3,%esi
  40f5ef:	je     41003a <TIFFSetField1+0x10b9>
  40f5f5:	cmp    $0x80e3,%esi
  40f5fb:	jg     40f65c <TIFFSetField1+0x6db>
  40f5fd:	cmp    $0x213,%esi
  40f603:	je     410269 <TIFFSetField1+0x12e8>
  40f609:	cmp    $0x213,%esi
  40f60f:	jl     4102a2 <TIFFSetField1+0x1321>
  40f615:	cmp    $0x214,%esi
  40f61b:	jne    40f1b8 <TIFFSetField1+0x237>
  40f621:	movzwl 0x70(%rdi),%edx
  40f625:	add    %edx,%edx
  40f627:	movslq %edx,%rdx
  40f62a:	mov    (%r12),%eax
  40f62e:	cmp    $0x2f,%eax
  40f631:	ja     4104a6 <TIFFSetField1+0x1525>
  40f637:	mov    %eax,%ecx
  40f639:	add    0x10(%r12),%rcx
  40f63e:	add    $0x8,%eax
  40f641:	mov    %eax,(%r12)
  40f645:	lea    0x198(%rbp),%rdi
  40f64c:	mov    (%rcx),%rsi
  40f64f:	callq  40eeca <setFloatArray>
  40f654:	mov    $0x1,%r12d
  40f65a:	jmp    40f6d3 <TIFFSetField1+0x752>
  40f65c:	cmp    $0x80e5,%esi
  40f662:	je     4101ee <TIFFSetField1+0x126d>
  40f668:	cmp    $0x80e5,%esi
  40f66e:	jl     41018d <TIFFSetField1+0x120c>
  40f674:	cmp    $0x80e6,%esi
  40f67a:	jne    40f1b8 <TIFFSetField1+0x237>
  40f680:	mov    (%rdx),%edx
  40f682:	cmp    $0x2f,%edx
  40f685:	ja     41017a <TIFFSetField1+0x11f9>
  40f68b:	mov    %edx,%eax
  40f68d:	add    0x10(%r12),%rax
  40f692:	add    $0x8,%edx
  40f695:	mov    %edx,(%r12)
  40f699:	mov    (%rax),%rax
  40f69c:	test   %rax,%rax
  40f69f:	je     4105d4 <TIFFSetField1+0x1653>
  40f6a5:	mov    %rax,0x58(%rbp)
  40f6a9:	mov    $0x1,%r12d
  40f6af:	jmp    40f6d3 <TIFFSetField1+0x752>
  40f6b1:	mov    (%rdx),%edx
  40f6b3:	cmp    $0x2f,%edx
  40f6b6:	ja     40f715 <TIFFSetField1+0x794>
  40f6b8:	mov    %edx,%eax
  40f6ba:	add    0x10(%r12),%rax
  40f6bf:	add    $0x8,%edx
  40f6c2:	mov    %edx,(%r12)
  40f6c6:	mov    (%rax),%rax
  40f6c9:	mov    %ax,0x60(%rbp)
  40f6cd:	mov    $0x1,%r12d
  40f6d3:	movzwl %bx,%ebx
  40f6d6:	mov    %ebx,%edi
  40f6d8:	callq  410ebe <TIFFFieldWithTag>
  40f6dd:	movzwl 0xc(%rax),%ecx
  40f6e1:	mov    $0x1,%r13d
  40f6e7:	shl    %cl,%r13d
  40f6ea:	mov    %ebx,%edi
  40f6ec:	callq  410ebe <TIFFFieldWithTag>
  40f6f1:	movzwl 0xc(%rax),%eax
  40f6f5:	shr    $0x5,%ax
  40f6f9:	movzwl %ax,%eax
  40f6fc:	mov    %r13d,%r13d
  40f6ff:	or     %r13,0x20(%rbp,%rax,8)
  40f704:	orw    $0x2,0xe(%rbp)
  40f709:	mov    %r12d,%eax
  40f70c:	pop    %rbx
  40f70d:	pop    %rbp
  40f70e:	pop    %r12
  40f710:	pop    %r13
  40f712:	pop    %r14
  40f714:	retq   
  40f715:	mov    0x8(%r12),%rax
  40f71a:	lea    0x8(%rax),%rdx
  40f71e:	mov    %rdx,0x8(%r12)
  40f723:	jmp    40f6c6 <TIFFSetField1+0x745>
  40f725:	mov    0x8(%r12),%rax
  40f72a:	lea    0x8(%rax),%rdx
  40f72e:	mov    %rdx,0x8(%r12)
  40f733:	jmpq   40f182 <TIFFSetField1+0x201>
  40f738:	mov    (%rdx),%edx
  40f73a:	cmp    $0x2f,%edx
  40f73d:	ja     40f75f <TIFFSetField1+0x7de>
  40f73f:	mov    %edx,%eax
  40f741:	add    0x10(%r12),%rax
  40f746:	add    $0x8,%edx
  40f749:	mov    %edx,(%r12)
  40f74d:	mov    (%rax),%rax
  40f750:	mov    %rax,0x38(%rbp)
  40f754:	mov    $0x1,%r12d
  40f75a:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f75f:	mov    0x8(%r12),%rax
  40f764:	lea    0x8(%rax),%rdx
  40f768:	mov    %rdx,0x8(%r12)
  40f76d:	jmp    40f74d <TIFFSetField1+0x7cc>
  40f76f:	mov    (%rdx),%edx
  40f771:	cmp    $0x2f,%edx
  40f774:	ja     40f795 <TIFFSetField1+0x814>
  40f776:	mov    %edx,%eax
  40f778:	add    0x10(%r12),%rax
  40f77d:	add    $0x8,%edx
  40f780:	mov    %edx,(%r12)
  40f784:	mov    (%rax),%eax
  40f786:	mov    %ax,0x62(%rbp)
  40f78a:	mov    $0x1,%r12d
  40f790:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f795:	mov    0x8(%r12),%rax
  40f79a:	lea    0x8(%rax),%rdx
  40f79e:	mov    %rdx,0x8(%r12)
  40f7a3:	jmp    40f784 <TIFFSetField1+0x803>
  40f7a5:	mov    (%rdx),%edx
  40f7a7:	cmp    $0x2f,%edx
  40f7aa:	ja     40f80f <TIFFSetField1+0x88e>
  40f7ac:	mov    %edx,%eax
  40f7ae:	add    0x10(%r12),%rax
  40f7b3:	add    $0x8,%edx
  40f7b6:	mov    %edx,(%r12)
  40f7ba:	mov    (%rax),%r13d
  40f7bd:	movzwl %r13w,%r12d
  40f7c1:	testb  $0x80,0x20(%rbp)
  40f7c5:	je     40f7ea <TIFFSetField1+0x869>
  40f7c7:	movzwl 0x66(%rbp),%eax
  40f7cb:	cmp    %r12,%rax
  40f7ce:	je     4105b3 <TIFFSetField1+0x1632>
  40f7d4:	mov    0x280(%rbp),%rdx
  40f7db:	test   %rdx,%rdx
  40f7de:	je     40f7ea <TIFFSetField1+0x869>
  40f7e0:	mov    %rbp,%rdi
  40f7e3:	mov    $0x0,%eax
  40f7e8:	callq  *%rdx
  40f7ea:	mov    %r12,%rsi
  40f7ed:	mov    %rbp,%rdi
  40f7f0:	mov    $0x0,%eax
  40f7f5:	callq  414417 <TIFFSetCompressionScheme>
  40f7fa:	mov    %eax,%r12d
  40f7fd:	test   %eax,%eax
  40f7ff:	je     40f1d7 <TIFFSetField1+0x256>
  40f805:	mov    %r13w,0x66(%rbp)
  40f80a:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f80f:	mov    0x8(%r12),%rax
  40f814:	lea    0x8(%rax),%rdx
  40f818:	mov    %rdx,0x8(%r12)
  40f81d:	jmp    40f7ba <TIFFSetField1+0x839>
  40f81f:	mov    0x8(%r12),%rax
  40f824:	lea    0x8(%rax),%rdx
  40f828:	mov    %rdx,0x8(%r12)
  40f82d:	jmpq   40f144 <TIFFSetField1+0x1c3>
  40f832:	mov    (%rdx),%edx
  40f834:	cmp    $0x2f,%edx
  40f837:	ja     40f858 <TIFFSetField1+0x8d7>
  40f839:	mov    %edx,%eax
  40f83b:	add    0x10(%r12),%rax
  40f840:	add    $0x8,%edx
  40f843:	mov    %edx,(%r12)
  40f847:	mov    (%rax),%eax
  40f849:	mov    %ax,0x6a(%rbp)
  40f84d:	mov    $0x1,%r12d
  40f853:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f858:	mov    0x8(%r12),%rax
  40f85d:	lea    0x8(%rax),%rdx
  40f861:	mov    %rdx,0x8(%r12)
  40f866:	jmp    40f847 <TIFFSetField1+0x8c6>
  40f868:	mov    0x8(%r12),%rax
  40f86d:	lea    0x8(%rax),%rdx
  40f871:	mov    %rdx,0x8(%r12)
  40f876:	jmpq   40f0b0 <TIFFSetField1+0x12f>
  40f87b:	mov    %dx,0x6c(%rbp)
  40f87f:	mov    $0x1,%r12d
  40f885:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f88a:	mov    (%rdx),%edx
  40f88c:	cmp    $0x2f,%edx
  40f88f:	ja     40f8b9 <TIFFSetField1+0x938>
  40f891:	mov    %edx,%eax
  40f893:	add    0x10(%r12),%rax
  40f898:	add    $0x8,%edx
  40f89b:	mov    %edx,(%r12)
  40f89f:	lea    0xf0(%rbp),%rdi
  40f8a6:	mov    (%rax),%rsi
  40f8a9:	callq  40ef21 <setString>
  40f8ae:	mov    $0x1,%r12d
  40f8b4:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f8b9:	mov    0x8(%r12),%rax
  40f8be:	lea    0x8(%rax),%rdx
  40f8c2:	mov    %rdx,0x8(%r12)
  40f8c7:	jmp    40f89f <TIFFSetField1+0x91e>
  40f8c9:	mov    (%rdx),%edx
  40f8cb:	cmp    $0x2f,%edx
  40f8ce:	ja     40f8f8 <TIFFSetField1+0x977>
  40f8d0:	mov    %edx,%eax
  40f8d2:	add    0x10(%r12),%rax
  40f8d7:	add    $0x8,%edx
  40f8da:	mov    %edx,(%r12)
  40f8de:	lea    0xf8(%rbp),%rdi
  40f8e5:	mov    (%rax),%rsi
  40f8e8:	callq  40ef21 <setString>
  40f8ed:	mov    $0x1,%r12d
  40f8f3:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f8f8:	mov    0x8(%r12),%rax
  40f8fd:	lea    0x8(%rax),%rdx
  40f901:	mov    %rdx,0x8(%r12)
  40f906:	jmp    40f8de <TIFFSetField1+0x95d>
  40f908:	mov    (%rdx),%edx
  40f90a:	cmp    $0x2f,%edx
  40f90d:	ja     40f937 <TIFFSetField1+0x9b6>
  40f90f:	mov    %edx,%eax
  40f911:	add    0x10(%r12),%rax
  40f916:	add    $0x8,%edx
  40f919:	mov    %edx,(%r12)
  40f91d:	lea    0x100(%rbp),%rdi
  40f924:	mov    (%rax),%rsi
  40f927:	callq  40ef21 <setString>
  40f92c:	mov    $0x1,%r12d
  40f932:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f937:	mov    0x8(%r12),%rax
  40f93c:	lea    0x8(%rax),%rdx
  40f940:	mov    %rdx,0x8(%r12)
  40f945:	jmp    40f91d <TIFFSetField1+0x99c>
  40f947:	mov    (%rdx),%edx
  40f949:	cmp    $0x2f,%edx
  40f94c:	ja     40f976 <TIFFSetField1+0x9f5>
  40f94e:	mov    %edx,%eax
  40f950:	add    0x10(%r12),%rax
  40f955:	add    $0x8,%edx
  40f958:	mov    %edx,(%r12)
  40f95c:	lea    0x108(%rbp),%rdi
  40f963:	mov    (%rax),%rsi
  40f966:	callq  40ef21 <setString>
  40f96b:	mov    $0x1,%r12d
  40f971:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f976:	mov    0x8(%r12),%rax
  40f97b:	lea    0x8(%rax),%rdx
  40f97f:	mov    %rdx,0x8(%r12)
  40f984:	jmp    40f95c <TIFFSetField1+0x9db>
  40f986:	mov    (%rdx),%edx
  40f988:	cmp    $0x2f,%edx
  40f98b:	ja     40f9b5 <TIFFSetField1+0xa34>
  40f98d:	mov    %edx,%eax
  40f98f:	add    0x10(%r12),%rax
  40f994:	add    $0x8,%edx
  40f997:	mov    %edx,(%r12)
  40f99b:	lea    0x110(%rbp),%rdi
  40f9a2:	mov    (%rax),%rsi
  40f9a5:	callq  40ef21 <setString>
  40f9aa:	mov    $0x1,%r12d
  40f9b0:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f9b5:	mov    0x8(%r12),%rax
  40f9ba:	lea    0x8(%rax),%rdx
  40f9be:	mov    %rdx,0x8(%r12)
  40f9c3:	jmp    40f99b <TIFFSetField1+0xa1a>
  40f9c5:	mov    (%rdx),%edx
  40f9c7:	cmp    $0x2f,%edx
  40f9ca:	ja     40f9f4 <TIFFSetField1+0xa73>
  40f9cc:	mov    %edx,%eax
  40f9ce:	add    0x10(%r12),%rax
  40f9d3:	add    $0x8,%edx
  40f9d6:	mov    %edx,(%r12)
  40f9da:	lea    0x118(%rbp),%rdi
  40f9e1:	mov    (%rax),%rsi
  40f9e4:	callq  40ef21 <setString>
  40f9e9:	mov    $0x1,%r12d
  40f9ef:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40f9f4:	mov    0x8(%r12),%rax
  40f9f9:	lea    0x8(%rax),%rdx
  40f9fd:	mov    %rdx,0x8(%r12)
  40fa02:	jmp    40f9da <TIFFSetField1+0xa59>
  40fa04:	mov    (%rdx),%edx
  40fa06:	cmp    $0x2f,%edx
  40fa09:	ja     40fa33 <TIFFSetField1+0xab2>
  40fa0b:	mov    %edx,%eax
  40fa0d:	add    0x10(%r12),%rax
  40fa12:	add    $0x8,%edx
  40fa15:	mov    %edx,(%r12)
  40fa19:	lea    0x120(%rbp),%rdi
  40fa20:	mov    (%rax),%rsi
  40fa23:	callq  40ef21 <setString>
  40fa28:	mov    $0x1,%r12d
  40fa2e:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fa33:	mov    0x8(%r12),%rax
  40fa38:	lea    0x8(%rax),%rdx
  40fa3c:	mov    %rdx,0x8(%r12)
  40fa41:	jmp    40fa19 <TIFFSetField1+0xa98>
  40fa43:	mov    (%rdx),%edx
  40fa45:	cmp    $0x2f,%edx
  40fa48:	ja     40fa72 <TIFFSetField1+0xaf1>
  40fa4a:	mov    %edx,%eax
  40fa4c:	add    0x10(%r12),%rax
  40fa51:	add    $0x8,%edx
  40fa54:	mov    %edx,(%r12)
  40fa58:	lea    0x128(%rbp),%rdi
  40fa5f:	mov    (%rax),%rsi
  40fa62:	callq  40ef21 <setString>
  40fa67:	mov    $0x1,%r12d
  40fa6d:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fa72:	mov    0x8(%r12),%rax
  40fa77:	lea    0x8(%rax),%rdx
  40fa7b:	mov    %rdx,0x8(%r12)
  40fa80:	jmp    40fa58 <TIFFSetField1+0xad7>
  40fa82:	mov    (%rdx),%edx
  40fa84:	cmp    $0x2f,%edx
  40fa87:	ja     40fab7 <TIFFSetField1+0xb36>
  40fa89:	mov    %edx,%eax
  40fa8b:	add    0x10(%r12),%rax
  40fa90:	add    $0x8,%edx
  40fa93:	mov    %edx,(%r12)
  40fa97:	mov    (%rax),%r12d
  40fa9a:	movslq %r12d,%rax
  40fa9d:	sub    $0x1,%rax
  40faa1:	cmp    $0x7,%rax
  40faa5:	ja     40fac7 <TIFFSetField1+0xb46>
  40faa7:	mov    %r12w,0x6e(%rbp)
  40faac:	mov    $0x1,%r12d
  40fab2:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fab7:	mov    0x8(%r12),%rax
  40fabc:	lea    0x8(%rax),%rdx
  40fac0:	mov    %rdx,0x8(%r12)
  40fac5:	jmp    40fa97 <TIFFSetField1+0xb16>
  40fac7:	mov    $0x112,%edi
  40facc:	callq  410ebe <TIFFFieldWithTag>
  40fad1:	mov    0x10(%rax),%rcx
  40fad5:	movslq %r12d,%rdx
  40fad8:	mov    $0x4199f0,%esi
  40fadd:	mov    0x0(%rbp),%rdi
  40fae1:	mov    $0x0,%eax
  40fae6:	callq  413526 <TIFFWarning>
  40faeb:	mov    $0x1,%r12d
  40faf1:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40faf6:	mov    (%rdx),%edx
  40faf8:	cmp    $0x2f,%edx
  40fafb:	ja     40fb2e <TIFFSetField1+0xbad>
  40fafd:	mov    %edx,%eax
  40faff:	add    0x10(%r12),%rax
  40fb04:	add    $0x8,%edx
  40fb07:	mov    %edx,(%r12)
  40fb0b:	mov    (%rax),%eax
  40fb0d:	movslq %eax,%r13
  40fb10:	test   %r13,%r13
  40fb13:	je     40f0c6 <TIFFSetField1+0x145>
  40fb19:	cmp    $0x4,%r13
  40fb1d:	jg     40fb3e <TIFFSetField1+0xbbd>
  40fb1f:	mov    %ax,0x70(%rbp)
  40fb23:	mov    $0x1,%r12d
  40fb29:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fb2e:	mov    0x8(%r12),%rax
  40fb33:	lea    0x8(%rax),%rdx
  40fb37:	mov    %rdx,0x8(%r12)
  40fb3c:	jmp    40fb0b <TIFFSetField1+0xb8a>
  40fb3e:	mov    %r13,%rdx
  40fb41:	mov    $0x419a18,%esi
  40fb46:	mov    0x0(%rbp),%rdi
  40fb4a:	mov    $0x0,%eax
  40fb4f:	callq  412a93 <TIFFError>
  40fb54:	jmpq   40f1d7 <TIFFSetField1+0x256>
  40fb59:	mov    (%rdx),%edx
  40fb5b:	cmp    $0x2f,%edx
  40fb5e:	ja     40fb9f <TIFFSetField1+0xc1e>
  40fb60:	mov    %edx,%eax
  40fb62:	add    0x10(%r12),%rax
  40fb67:	add    $0x8,%edx
  40fb6a:	mov    %edx,(%r12)
  40fb6e:	mov    (%rax),%rax
  40fb71:	test   %rax,%rax
  40fb74:	je     4105c9 <TIFFSetField1+0x1648>
  40fb7a:	mov    %rax,0x78(%rbp)
  40fb7e:	mov    $0x1,%r12d
  40fb84:	testb  $0x2,0x20(%rbp)
  40fb88:	jne    40f6d3 <TIFFSetField1+0x752>
  40fb8e:	mov    %rax,0x50(%rbp)
  40fb92:	mov    0x30(%rbp),%rax
  40fb96:	mov    %rax,0x48(%rbp)
  40fb9a:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fb9f:	mov    0x8(%r12),%rax
  40fba4:	lea    0x8(%rax),%rdx
  40fba8:	mov    %rdx,0x8(%r12)
  40fbad:	jmp    40fb6e <TIFFSetField1+0xbed>
  40fbaf:	mov    0x8(%r12),%rax
  40fbb4:	lea    0x8(%rax),%rdx
  40fbb8:	mov    %rdx,0x8(%r12)
  40fbbd:	jmpq   40f02e <TIFFSetField1+0xad>
  40fbc2:	mov    (%rdx),%edx
  40fbc4:	cmp    $0x2f,%edx
  40fbc7:	ja     40fbec <TIFFSetField1+0xc6b>
  40fbc9:	mov    %edx,%eax
  40fbcb:	add    0x10(%r12),%rax
  40fbd0:	add    $0x8,%edx
  40fbd3:	mov    %edx,(%r12)
  40fbd7:	movzwl (%rax),%eax
  40fbda:	mov    %rax,0x88(%rbp)
  40fbe1:	mov    $0x1,%r12d
  40fbe7:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fbec:	mov    0x8(%r12),%rax
  40fbf1:	lea    0x8(%rax),%rdx
  40fbf5:	mov    %rdx,0x8(%r12)
  40fbfa:	jmp    40fbd7 <TIFFSetField1+0xc56>
  40fbfc:	mov    0x4(%rdx),%edx
  40fbff:	cmp    $0xaf,%edx
  40fc05:	ja     40fc31 <TIFFSetField1+0xcb0>
  40fc07:	mov    %edx,%eax
  40fc09:	add    0x10(%r12),%rax
  40fc0e:	add    $0x10,%edx
  40fc11:	mov    %edx,0x4(%r12)
  40fc16:	pxor   %xmm0,%xmm0
  40fc1a:	cvtsd2ss (%rax),%xmm0
  40fc1e:	movss  %xmm0,0x90(%rbp)
  40fc26:	mov    $0x1,%r12d
  40fc2c:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fc31:	mov    0x8(%r12),%rax
  40fc36:	lea    0x8(%rax),%rdx
  40fc3a:	mov    %rdx,0x8(%r12)
  40fc3f:	jmp    40fc16 <TIFFSetField1+0xc95>
  40fc41:	mov    0x4(%rdx),%edx
  40fc44:	cmp    $0xaf,%edx
  40fc4a:	ja     40fc76 <TIFFSetField1+0xcf5>
  40fc4c:	mov    %edx,%eax
  40fc4e:	add    0x10(%r12),%rax
  40fc53:	add    $0x10,%edx
  40fc56:	mov    %edx,0x4(%r12)
  40fc5b:	pxor   %xmm1,%xmm1
  40fc5f:	cvtsd2ss (%rax),%xmm1
  40fc63:	movss  %xmm1,0x94(%rbp)
  40fc6b:	mov    $0x1,%r12d
  40fc71:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fc76:	mov    0x8(%r12),%rax
  40fc7b:	lea    0x8(%rax),%rdx
  40fc7f:	mov    %rdx,0x8(%r12)
  40fc84:	jmp    40fc5b <TIFFSetField1+0xcda>
  40fc86:	mov    0x8(%r12),%rax
  40fc8b:	lea    0x8(%rax),%rdx
  40fc8f:	mov    %rdx,0x8(%r12)
  40fc94:	jmpq   40f213 <TIFFSetField1+0x292>
  40fc99:	mov    %r13w,0x9a(%rbp)
  40fca1:	mov    $0x1,%r12d
  40fca7:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fcac:	mov    (%rdx),%edx
  40fcae:	cmp    $0x2f,%edx
  40fcb1:	ja     40fcdb <TIFFSetField1+0xd5a>
  40fcb3:	mov    %edx,%eax
  40fcb5:	add    0x10(%r12),%rax
  40fcba:	add    $0x8,%edx
  40fcbd:	mov    %edx,(%r12)
  40fcc1:	lea    0x130(%rbp),%rdi
  40fcc8:	mov    (%rax),%rsi
  40fccb:	callq  40ef21 <setString>
  40fcd0:	mov    $0x1,%r12d
  40fcd6:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fcdb:	mov    0x8(%r12),%rax
  40fce0:	lea    0x8(%rax),%rdx
  40fce4:	mov    %rdx,0x8(%r12)
  40fce9:	jmp    40fcc1 <TIFFSetField1+0xd40>
  40fceb:	mov    0x4(%rdx),%edx
  40fcee:	cmp    $0xaf,%edx
  40fcf4:	ja     40fd20 <TIFFSetField1+0xd9f>
  40fcf6:	mov    %edx,%eax
  40fcf8:	add    0x10(%r12),%rax
  40fcfd:	add    $0x10,%edx
  40fd00:	mov    %edx,0x4(%r12)
  40fd05:	pxor   %xmm2,%xmm2
  40fd09:	cvtsd2ss (%rax),%xmm2
  40fd0d:	movss  %xmm2,0x9c(%rbp)
  40fd15:	mov    $0x1,%r12d
  40fd1b:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fd20:	mov    0x8(%r12),%rax
  40fd25:	lea    0x8(%rax),%rdx
  40fd29:	mov    %rdx,0x8(%r12)
  40fd2e:	jmp    40fd05 <TIFFSetField1+0xd84>
  40fd30:	mov    0x4(%rdx),%edx
  40fd33:	cmp    $0xaf,%edx
  40fd39:	ja     40fd65 <TIFFSetField1+0xde4>
  40fd3b:	mov    %edx,%eax
  40fd3d:	add    0x10(%r12),%rax
  40fd42:	add    $0x10,%edx
  40fd45:	mov    %edx,0x4(%r12)
  40fd4a:	pxor   %xmm3,%xmm3
  40fd4e:	cvtsd2ss (%rax),%xmm3
  40fd52:	movss  %xmm3,0xa0(%rbp)
  40fd5a:	mov    $0x1,%r12d
  40fd60:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fd65:	mov    0x8(%r12),%rax
  40fd6a:	lea    0x8(%rax),%rdx
  40fd6e:	mov    %rdx,0x8(%r12)
  40fd73:	jmp    40fd4a <TIFFSetField1+0xdc9>
  40fd75:	mov    0x8(%r12),%rax
  40fd7a:	lea    0x8(%rax),%rdx
  40fd7e:	mov    %rdx,0x8(%r12)
  40fd83:	jmpq   40f280 <TIFFSetField1+0x2ff>
  40fd88:	mov    (%rdx),%edx
  40fd8a:	cmp    $0x2f,%edx
  40fd8d:	ja     40fdb2 <TIFFSetField1+0xe31>
  40fd8f:	mov    %edx,%eax
  40fd91:	add    0x10(%r12),%rax
  40fd96:	add    $0x8,%edx
  40fd99:	mov    %edx,(%r12)
  40fd9d:	mov    (%rax),%rax
  40fda0:	mov    %rax,0xb0(%rbp)
  40fda7:	mov    $0x1,%r12d
  40fdad:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fdb2:	mov    0x8(%r12),%rax
  40fdb7:	lea    0x8(%rax),%rdx
  40fdbb:	mov    %rdx,0x8(%r12)
  40fdc0:	jmp    40fd9d <TIFFSetField1+0xe1c>
  40fdc2:	mov    (%rdx),%edx
  40fdc4:	cmp    $0x2f,%edx
  40fdc7:	ja     40fdef <TIFFSetField1+0xe6e>
  40fdc9:	mov    %edx,%eax
  40fdcb:	add    0x10(%r12),%rax
  40fdd0:	add    $0x8,%edx
  40fdd3:	mov    %edx,(%r12)
  40fdd7:	mov    (%rax),%r13d
  40fdda:	movslq %r13d,%rax
  40fddd:	sub    $0x1,%rax
  40fde1:	cmp    $0x2,%rax
  40fde5:	jbe    40fdff <TIFFSetField1+0xe7e>
  40fde7:	movslq %r13d,%r13
  40fdea:	jmpq   40f0c6 <TIFFSetField1+0x145>
  40fdef:	mov    0x8(%r12),%rax
  40fdf4:	lea    0x8(%rax),%rdx
  40fdf8:	mov    %rdx,0x8(%r12)
  40fdfd:	jmp    40fdd7 <TIFFSetField1+0xe56>
  40fdff:	mov    %r13w,0x98(%rbp)
  40fe07:	mov    $0x1,%r12d
  40fe0d:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fe12:	mov    (%rdx),%edx
  40fe14:	cmp    $0x2f,%edx
  40fe17:	ja     40fe5b <TIFFSetField1+0xeda>
  40fe19:	mov    %edx,%eax
  40fe1b:	add    0x10(%r12),%rax
  40fe20:	add    $0x8,%edx
  40fe23:	mov    %edx,(%r12)
  40fe27:	mov    (%rax),%eax
  40fe29:	mov    %ax,0xb8(%rbp)
  40fe30:	mov    (%r12),%eax
  40fe34:	cmp    $0x2f,%eax
  40fe37:	ja     40fe6b <TIFFSetField1+0xeea>
  40fe39:	mov    %eax,%edx
  40fe3b:	add    0x10(%r12),%rdx
  40fe40:	add    $0x8,%eax
  40fe43:	mov    %eax,(%r12)
  40fe47:	mov    (%rdx),%eax
  40fe49:	mov    %ax,0xba(%rbp)
  40fe50:	mov    $0x1,%r12d
  40fe56:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fe5b:	mov    0x8(%r12),%rax
  40fe60:	lea    0x8(%rax),%rdx
  40fe64:	mov    %rdx,0x8(%r12)
  40fe69:	jmp    40fe27 <TIFFSetField1+0xea6>
  40fe6b:	mov    0x8(%r12),%rdx
  40fe70:	lea    0x8(%rdx),%rax
  40fe74:	mov    %rax,0x8(%r12)
  40fe79:	jmp    40fe47 <TIFFSetField1+0xec6>
  40fe7b:	mov    (%rdx),%edx
  40fe7d:	cmp    $0x2f,%edx
  40fe80:	ja     40fec4 <TIFFSetField1+0xf43>
  40fe82:	mov    %edx,%eax
  40fe84:	add    0x10(%r12),%rax
  40fe89:	add    $0x8,%edx
  40fe8c:	mov    %edx,(%r12)
  40fe90:	mov    (%rax),%eax
  40fe92:	mov    %ax,0xe8(%rbp)
  40fe99:	mov    (%r12),%eax
  40fe9d:	cmp    $0x2f,%eax
  40fea0:	ja     40fed4 <TIFFSetField1+0xf53>
  40fea2:	mov    %eax,%edx
  40fea4:	add    0x10(%r12),%rdx
  40fea9:	add    $0x8,%eax
  40feac:	mov    %eax,(%r12)
  40feb0:	mov    (%rdx),%eax
  40feb2:	mov    %ax,0xea(%rbp)
  40feb9:	mov    $0x1,%r12d
  40febf:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40fec4:	mov    0x8(%r12),%rax
  40fec9:	lea    0x8(%rax),%rdx
  40fecd:	mov    %rdx,0x8(%r12)
  40fed2:	jmp    40fe90 <TIFFSetField1+0xf0f>
  40fed4:	mov    0x8(%r12),%rdx
  40fed9:	lea    0x8(%rdx),%rax
  40fedd:	mov    %rax,0x8(%r12)
  40fee2:	jmp    40feb0 <TIFFSetField1+0xf2f>
  40fee4:	movzwl 0x62(%rdi),%ecx
  40fee8:	mov    $0x1,%r13d
  40feee:	shl    %cl,%r13
  40fef1:	mov    (%rdx),%eax
  40fef3:	cmp    $0x2f,%eax
  40fef6:	ja     40ff72 <TIFFSetField1+0xff1>
  40fef8:	mov    %eax,%ecx
  40fefa:	add    0x10(%rdx),%rcx
  40fefe:	add    $0x8,%eax
  40ff01:	mov    %eax,(%rdx)
  40ff03:	lea    0xd0(%rbp),%rdi
  40ff0a:	mov    %r13,%rdx
  40ff0d:	mov    (%rcx),%rsi
  40ff10:	callq  40ee74 <setShortArray>
  40ff15:	mov    (%r12),%eax
  40ff19:	cmp    $0x2f,%eax
  40ff1c:	ja     40ff80 <TIFFSetField1+0xfff>
  40ff1e:	mov    %eax,%ecx
  40ff20:	add    0x10(%r12),%rcx
  40ff25:	add    $0x8,%eax
  40ff28:	mov    %eax,(%r12)
  40ff2c:	lea    0xd8(%rbp),%rdi
  40ff33:	mov    %r13,%rdx
  40ff36:	mov    (%rcx),%rsi
  40ff39:	callq  40ee74 <setShortArray>
  40ff3e:	mov    (%r12),%eax
  40ff42:	cmp    $0x2f,%eax
  40ff45:	ja     40ff90 <TIFFSetField1+0x100f>
  40ff47:	mov    %eax,%ecx
  40ff49:	add    0x10(%r12),%rcx
  40ff4e:	add    $0x8,%eax
  40ff51:	mov    %eax,(%r12)
  40ff55:	lea    0xe0(%rbp),%rdi
  40ff5c:	mov    %r13,%rdx
  40ff5f:	mov    (%rcx),%rsi
  40ff62:	callq  40ee74 <setShortArray>
  40ff67:	mov    $0x1,%r12d
  40ff6d:	jmpq   40f6d3 <TIFFSetField1+0x752>
  40ff72:	mov    0x8(%rdx),%rcx
  40ff76:	lea    0x8(%rcx),%rax
  40ff7a:	mov    %rax,0x8(%rdx)
  40ff7e:	jmp    40ff03 <TIFFSetField1+0xf82>
  40ff80:	mov    0x8(%r12),%rcx
  40ff85:	lea    0x8(%rcx),%rax
  40ff89:	mov    %rax,0x8(%r12)
  40ff8e:	jmp    40ff2c <TIFFSetField1+0xfab>
  40ff90:	mov    0x8(%r12),%rcx
  40ff95:	lea    0x8(%rcx),%rax
  40ff99:	mov    %rax,0x8(%r12)
  40ff9e:	jmp    40ff55 <TIFFSetField1+0xfd4>
  40ffa0:	mov    0x8(%r12),%rax
  40ffa5:	lea    0x8(%rax),%rdx
  40ffa9:	mov    %rdx,0x8(%r12)
  40ffae:	jmpq   40f413 <TIFFSetField1+0x492>
  40ffb3:	mov    (%rdx),%edx
  40ffb5:	cmp    $0x2f,%edx
  40ffb8:	ja     41001a <TIFFSetField1+0x1099>
  40ffba:	mov    %edx,%eax
  40ffbc:	add    0x10(%r12),%rax
  40ffc1:	add    $0x8,%edx
  40ffc4:	mov    %edx,(%r12)
  40ffc8:	movslq (%rax),%r13
  40ffcb:	movzwl 0x70(%rbp),%eax
  40ffcf:	cmp    %r13,%rax
  40ffd2:	jl     40f0c6 <TIFFSetField1+0x145>
  40ffd8:	cmp    $0x1,%r13
  40ffdc:	jne    40f0c6 <TIFFSetField1+0x145>
  40ffe2:	mov    (%r12),%edx
  40ffe6:	cmp    $0x2f,%edx
  40ffe9:	ja     41002a <TIFFSetField1+0x10a9>
  40ffeb:	mov    %edx,%eax
  40ffed:	add    0x10(%r12),%rax
  40fff2:	add    $0x8,%edx
  40fff5:	mov    %edx,(%r12)
  40fff9:	movslq (%rax),%r13
  40fffc:	cmp    $0x1,%r13
  410000:	jne    40f0c6 <TIFFSetField1+0x145>
  410006:	movw   $0x1,0xbc(%rbp)
  41000f:	mov    $0x1,%r12d
  410015:	jmpq   40f6d3 <TIFFSetField1+0x752>
  41001a:	mov    0x8(%r12),%rax
  41001f:	lea    0x8(%rax),%rdx
  410023:	mov    %rdx,0x8(%r12)
  410028:	jmp    40ffc8 <TIFFSetField1+0x1047>
  41002a:	mov    0x8(%r12),%rax
  41002f:	lea    0x8(%rax),%rdx
  410033:	mov    %rdx,0x8(%r12)
  410038:	jmp    40fff9 <TIFFSetField1+0x1078>
  41003a:	mov    (%rdx),%edx
  41003c:	cmp    $0x2f,%edx
  41003f:	ja     410063 <TIFFSetField1+0x10e2>
  410041:	mov    %edx,%eax
  410043:	add    0x10(%r12),%rax
  410048:	add    $0x8,%edx
  41004b:	mov    %edx,(%r12)
  41004f:	mov    (%rax),%eax
  410051:	mov    %ax,0xbc(%rbp)
  410058:	mov    $0x1,%r12d
  41005e:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410063:	mov    0x8(%r12),%rax
  410068:	lea    0x8(%rax),%rdx
  41006c:	mov    %rdx,0x8(%r12)
  410071:	jmp    41004f <TIFFSetField1+0x10ce>
  410073:	mov    (%rdx),%edx
  410075:	cmp    $0x2f,%edx
  410078:	ja     41009d <TIFFSetField1+0x111c>
  41007a:	mov    %edx,%eax
  41007c:	add    0x10(%r12),%rax
  410081:	add    $0x8,%edx
  410084:	mov    %edx,(%r12)
  410088:	mov    (%rax),%rax
  41008b:	mov    %rax,0xc8(%rbp)
  410092:	mov    $0x1,%r12d
  410098:	jmpq   40f6d3 <TIFFSetField1+0x752>
  41009d:	mov    0x8(%r12),%rax
  4100a2:	lea    0x8(%rax),%rdx
  4100a6:	mov    %rdx,0x8(%r12)
  4100ab:	jmp    410088 <TIFFSetField1+0x1107>
  4100ad:	mov    (%rdx),%edx
  4100af:	cmp    $0x2f,%edx
  4100b2:	ja     4100d6 <TIFFSetField1+0x1155>
  4100b4:	mov    %edx,%eax
  4100b6:	add    0x10(%r12),%rax
  4100bb:	add    $0x8,%edx
  4100be:	mov    %edx,(%r12)
  4100c2:	mov    (%rax),%eax
  4100c4:	mov    %ax,0xbe(%rbp)
  4100cb:	mov    $0x1,%r12d
  4100d1:	jmpq   40f6d3 <TIFFSetField1+0x752>
  4100d6:	mov    0x8(%r12),%rax
  4100db:	lea    0x8(%rax),%rdx
  4100df:	mov    %rdx,0x8(%r12)
  4100e4:	jmp    4100c2 <TIFFSetField1+0x1141>
  4100e6:	mov    (%rdx),%edx
  4100e8:	cmp    $0x2f,%edx
  4100eb:	ja     410110 <TIFFSetField1+0x118f>
  4100ed:	mov    %edx,%eax
  4100ef:	add    0x10(%r12),%rax
  4100f4:	add    $0x8,%edx
  4100f7:	mov    %edx,(%r12)
  4100fb:	mov    (%rax),%rax
  4100fe:	mov    %ax,0xc0(%rbp)
  410105:	mov    $0x1,%r12d
  41010b:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410110:	mov    0x8(%r12),%rax
  410115:	lea    0x8(%rax),%rdx
  410119:	mov    %rdx,0x8(%r12)
  41011e:	jmp    4100fb <TIFFSetField1+0x117a>
  410120:	mov    (%rdx),%edx
  410122:	cmp    $0x2f,%edx
  410125:	ja     410157 <TIFFSetField1+0x11d6>
  410127:	mov    %edx,%eax
  410129:	add    0x10(%r12),%rax
  41012e:	add    $0x8,%edx
  410131:	mov    %edx,(%r12)
  410135:	mov    (%rax),%r13
  410138:	test   $0x7,%r13b
  41013c:	jne    40f0c6 <TIFFSetField1+0x145>
  410142:	mov    %r13,0x48(%rbp)
  410146:	orw    $0x80,0xe(%rbp)
  41014c:	mov    $0x1,%r12d
  410152:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410157:	mov    0x8(%r12),%rax
  41015c:	lea    0x8(%rax),%rdx
  410160:	mov    %rdx,0x8(%r12)
  410165:	jmp    410135 <TIFFSetField1+0x11b4>
  410167:	mov    0x8(%r12),%rax
  41016c:	lea    0x8(%rax),%rdx
  410170:	mov    %rdx,0x8(%r12)
  410175:	jmpq   40f35c <TIFFSetField1+0x3db>
  41017a:	mov    0x8(%r12),%rax
  41017f:	lea    0x8(%rax),%rdx
  410183:	mov    %rdx,0x8(%r12)
  410188:	jmpq   40f699 <TIFFSetField1+0x718>
  41018d:	mov    (%r12),%edx
  410191:	cmp    $0x2f,%edx
  410194:	ja     4101cc <TIFFSetField1+0x124b>
  410196:	mov    %edx,%eax
  410198:	add    0x10(%r12),%rax
  41019d:	add    $0x8,%edx
  4101a0:	mov    %edx,(%r12)
  4101a4:	mov    (%rax),%eax
  4101a6:	movslq %eax,%r13
  4101a9:	cmp    $0x80e4,%ebx
  4101af:	jne    4101dc <TIFFSetField1+0x125b>
  4101b1:	test   %r13,%r13
  4101b4:	jne    4101dc <TIFFSetField1+0x125b>
  4101b6:	mov    $0x4,%r13d
  4101bc:	mov    %r13w,0x64(%rbp)
  4101c1:	mov    $0x1,%r12d
  4101c7:	jmpq   40f6d3 <TIFFSetField1+0x752>
  4101cc:	mov    0x8(%r12),%rax
  4101d1:	lea    0x8(%rax),%rdx
  4101d5:	mov    %rdx,0x8(%r12)
  4101da:	jmp    4101a4 <TIFFSetField1+0x1223>
  4101dc:	cltq   
  4101de:	sub    $0x1,%rax
  4101e2:	cmp    $0x3,%rax
  4101e6:	ja     40f0c6 <TIFFSetField1+0x145>
  4101ec:	jmp    4101bc <TIFFSetField1+0x123b>
  4101ee:	mov    (%rdx),%edx
  4101f0:	cmp    $0x2f,%edx
  4101f3:	ja     410215 <TIFFSetField1+0x1294>
  4101f5:	mov    %edx,%eax
  4101f7:	add    0x10(%r12),%rax
  4101fc:	add    $0x8,%edx
  4101ff:	mov    %edx,(%r12)
  410203:	mov    (%rax),%rax
  410206:	mov    %rax,0x40(%rbp)
  41020a:	mov    $0x1,%r12d
  410210:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410215:	mov    0x8(%r12),%rax
  41021a:	lea    0x8(%rax),%rdx
  41021e:	mov    %rdx,0x8(%r12)
  410223:	jmp    410203 <TIFFSetField1+0x1282>
  410225:	mov    (%rdx),%edx
  410227:	cmp    $0x2f,%edx
  41022a:	ja     410259 <TIFFSetField1+0x12d8>
  41022c:	mov    %edx,%eax
  41022e:	add    0x10(%r12),%rax
  410233:	add    $0x8,%edx
  410236:	mov    %edx,(%r12)
  41023a:	lea    0x158(%rbp),%rdi
  410241:	mov    $0x3,%edx
  410246:	mov    (%rax),%rsi
  410249:	callq  40eeca <setFloatArray>
  41024e:	mov    $0x1,%r12d
  410254:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410259:	mov    0x8(%r12),%rax
  41025e:	lea    0x8(%rax),%rdx
  410262:	mov    %rdx,0x8(%r12)
  410267:	jmp    41023a <TIFFSetField1+0x12b9>
  410269:	mov    (%rdx),%edx
  41026b:	cmp    $0x2f,%edx
  41026e:	ja     410292 <TIFFSetField1+0x1311>
  410270:	mov    %edx,%eax
  410272:	add    0x10(%r12),%rax
  410277:	add    $0x8,%edx
  41027a:	mov    %edx,(%r12)
  41027e:	mov    (%rax),%eax
  410280:	mov    %ax,0x164(%rbp)
  410287:	mov    $0x1,%r12d
  41028d:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410292:	mov    0x8(%r12),%rax
  410297:	lea    0x8(%rax),%rdx
  41029b:	mov    %rdx,0x8(%r12)
  4102a0:	jmp    41027e <TIFFSetField1+0x12fd>
  4102a2:	mov    (%rdx),%edx
  4102a4:	cmp    $0x2f,%edx
  4102a7:	ja     4102eb <TIFFSetField1+0x136a>
  4102a9:	mov    %edx,%eax
  4102ab:	add    0x10(%r12),%rax
  4102b0:	add    $0x8,%edx
  4102b3:	mov    %edx,(%r12)
  4102b7:	mov    (%rax),%eax
  4102b9:	mov    %ax,0x160(%rbp)
  4102c0:	mov    (%r12),%eax
  4102c4:	cmp    $0x2f,%eax
  4102c7:	ja     4102fb <TIFFSetField1+0x137a>
  4102c9:	mov    %eax,%edx
  4102cb:	add    0x10(%r12),%rdx
  4102d0:	add    $0x8,%eax
  4102d3:	mov    %eax,(%r12)
  4102d7:	mov    (%rdx),%eax
  4102d9:	mov    %ax,0x162(%rbp)
  4102e0:	mov    $0x1,%r12d
  4102e6:	jmpq   40f6d3 <TIFFSetField1+0x752>
  4102eb:	mov    0x8(%r12),%rax
  4102f0:	lea    0x8(%rax),%rdx
  4102f4:	mov    %rdx,0x8(%r12)
  4102f9:	jmp    4102b7 <TIFFSetField1+0x1336>
  4102fb:	mov    0x8(%r12),%rdx
  410300:	lea    0x8(%rdx),%rax
  410304:	mov    %rax,0x8(%r12)
  410309:	jmp    4102d7 <TIFFSetField1+0x1356>
  41030b:	mov    0x8(%r12),%rax
  410310:	lea    0x8(%rax),%rdx
  410314:	mov    %rdx,0x8(%r12)
  410319:	jmpq   40f5d5 <TIFFSetField1+0x654>
  41031e:	mov    (%rdx),%edx
  410320:	cmp    $0x2f,%edx
  410323:	ja     410347 <TIFFSetField1+0x13c6>
  410325:	mov    %edx,%eax
  410327:	add    0x10(%r12),%rax
  41032c:	add    $0x8,%edx
  41032f:	mov    %edx,(%r12)
  410333:	mov    (%rax),%eax
  410335:	mov    %ax,0x168(%rbp)
  41033c:	mov    $0x1,%r12d
  410342:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410347:	mov    0x8(%r12),%rax
  41034c:	lea    0x8(%rax),%rdx
  410350:	mov    %rdx,0x8(%r12)
  410355:	jmp    410333 <TIFFSetField1+0x13b2>
  410357:	mov    0x8(%rdx),%rdx
  41035b:	lea    0x8(%rdx),%rax
  41035f:	mov    %rax,0x8(%r12)
  410364:	jmpq   40f4e7 <TIFFSetField1+0x566>
  410369:	movzwl 0x70(%rdi),%edx
  41036d:	mov    (%r12),%eax
  410371:	cmp    $0x2f,%eax
  410374:	ja     41039e <TIFFSetField1+0x141d>
  410376:	mov    %eax,%ecx
  410378:	add    0x10(%r12),%rcx
  41037d:	add    $0x8,%eax
  410380:	mov    %eax,(%r12)
  410384:	lea    0x178(%rbp),%rdi
  41038b:	mov    (%rcx),%rsi
  41038e:	callq  40ed74 <setJPEGCTable>
  410393:	mov    $0x1,%r12d
  410399:	jmpq   40f6d3 <TIFFSetField1+0x752>
  41039e:	mov    0x8(%r12),%rcx
  4103a3:	lea    0x8(%rcx),%rax
  4103a7:	mov    %rax,0x8(%r12)
  4103ac:	jmp    410384 <TIFFSetField1+0x1403>
  4103ae:	movzwl 0x70(%rdi),%edx
  4103b2:	mov    (%r12),%eax
  4103b6:	cmp    $0x2f,%eax
  4103b9:	ja     4103e3 <TIFFSetField1+0x1462>
  4103bb:	mov    %eax,%ecx
  4103bd:	add    0x10(%r12),%rcx
  4103c2:	add    $0x8,%eax
  4103c5:	mov    %eax,(%r12)
  4103c9:	lea    0x180(%rbp),%rdi
  4103d0:	mov    (%rcx),%rsi
  4103d3:	callq  40ed74 <setJPEGCTable>
  4103d8:	mov    $0x1,%r12d
  4103de:	jmpq   40f6d3 <TIFFSetField1+0x752>
  4103e3:	mov    0x8(%r12),%rcx
  4103e8:	lea    0x8(%rcx),%rax
  4103ec:	mov    %rax,0x8(%r12)
  4103f1:	jmp    4103c9 <TIFFSetField1+0x1448>
  4103f3:	mov    (%rdx),%edx
  4103f5:	cmp    $0x2f,%edx
  4103f8:	ja     410427 <TIFFSetField1+0x14a6>
  4103fa:	mov    %edx,%eax
  4103fc:	add    0x10(%r12),%rax
  410401:	add    $0x8,%edx
  410404:	mov    %edx,(%r12)
  410408:	lea    0x188(%rbp),%rdi
  41040f:	mov    $0x2,%edx
  410414:	mov    (%rax),%rsi
  410417:	callq  40eeca <setFloatArray>
  41041c:	mov    $0x1,%r12d
  410422:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410427:	mov    0x8(%r12),%rax
  41042c:	lea    0x8(%rax),%rdx
  410430:	mov    %rdx,0x8(%r12)
  410435:	jmp    410408 <TIFFSetField1+0x1487>
  410437:	mov    0x8(%r12),%rax
  41043c:	lea    0x8(%rax),%rdx
  410440:	mov    %rdx,0x8(%r12)
  410445:	jmpq   40f3c3 <TIFFSetField1+0x442>
  41044a:	mov    0x8(%r12),%rcx
  41044f:	lea    0x8(%rcx),%rax
  410453:	mov    %rax,0x8(%r12)
  410458:	movslq %r13d,%rax
  41045b:	lea    0x1a0(%rbp,%rax,8),%rdi
  410463:	mov    (%rcx),%rsi
  410466:	callq  40ee74 <setShortArray>
  41046b:	add    $0x1,%r13d
  41046f:	movzwl 0x70(%rbp),%eax
  410473:	cmp    %r13d,%eax
  410476:	jle    41049b <TIFFSetField1+0x151a>
  410478:	movzwl 0x62(%rbp),%ecx
  41047c:	mov    %r14,%rdx
  41047f:	shl    %cl,%rdx
  410482:	mov    (%r12),%eax
  410486:	cmp    $0x2f,%eax
  410489:	ja     41044a <TIFFSetField1+0x14c9>
  41048b:	mov    %eax,%ecx
  41048d:	add    0x10(%r12),%rcx
  410492:	add    $0x8,%eax
  410495:	mov    %eax,(%r12)
  410499:	jmp    410458 <TIFFSetField1+0x14d7>
  41049b:	mov    $0x1,%r12d
  4104a1:	jmpq   40f6d3 <TIFFSetField1+0x752>
  4104a6:	mov    0x8(%r12),%rcx
  4104ab:	lea    0x8(%rcx),%rax
  4104af:	mov    %rax,0x8(%r12)
  4104b4:	jmpq   40f645 <TIFFSetField1+0x6c4>
  4104b9:	mov    0x8(%r12),%rax
  4104be:	lea    0x8(%rax),%rdx
  4104c2:	mov    %rdx,0x8(%r12)
  4104c7:	jmpq   40f461 <TIFFSetField1+0x4e0>
  4104cc:	mov    (%rdx),%edx
  4104ce:	cmp    $0x2f,%edx
  4104d1:	ja     410515 <TIFFSetField1+0x1594>
  4104d3:	mov    %edx,%eax
  4104d5:	add    0x10(%r12),%rax
  4104da:	add    $0x8,%edx
  4104dd:	mov    %edx,(%r12)
  4104e1:	mov    (%rax),%eax
  4104e3:	mov    %ax,0x1c2(%rbp)
  4104ea:	mov    (%r12),%eax
  4104ee:	cmp    $0x2f,%eax
  4104f1:	ja     410525 <TIFFSetField1+0x15a4>
  4104f3:	mov    %eax,%edx
  4104f5:	add    0x10(%r12),%rdx
  4104fa:	add    $0x8,%eax
  4104fd:	mov    %eax,(%r12)
  410501:	mov    (%rdx),%eax
  410503:	mov    %ax,0x1c4(%rbp)
  41050a:	mov    $0x1,%r12d
  410510:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410515:	mov    0x8(%r12),%rax
  41051a:	lea    0x8(%rax),%rdx
  41051e:	mov    %rdx,0x8(%r12)
  410523:	jmp    4104e1 <TIFFSetField1+0x1560>
  410525:	mov    0x8(%r12),%rdx
  41052a:	lea    0x8(%rdx),%rax
  41052e:	mov    %rax,0x8(%r12)
  410533:	jmp    410501 <TIFFSetField1+0x1580>
  410535:	mov    (%rdx),%edx
  410537:	cmp    $0x2f,%edx
  41053a:	ja     410564 <TIFFSetField1+0x15e3>
  41053c:	mov    %edx,%eax
  41053e:	add    0x10(%r12),%rax
  410543:	add    $0x8,%edx
  410546:	mov    %edx,(%r12)
  41054a:	lea    0x1c8(%rbp),%rdi
  410551:	mov    (%rax),%rsi
  410554:	callq  40ef21 <setString>
  410559:	mov    $0x1,%r12d
  41055f:	jmpq   40f6d3 <TIFFSetField1+0x752>
  410564:	mov    0x8(%r12),%rax
  410569:	lea    0x8(%rax),%rdx
  41056d:	mov    %rdx,0x8(%r12)
  410572:	jmp    41054a <TIFFSetField1+0x15c9>
  410574:	mov    (%rdx),%edx
  410576:	cmp    $0x2f,%edx
  410579:	ja     4105a3 <TIFFSetField1+0x1622>
  41057b:	mov    %edx,%eax
  41057d:	add    0x10(%r12),%rax
  410582:	add    $0x8,%edx
  410585:	mov    %edx,(%r12)
  410589:	lea    0x1d0(%rbp),%rdi
  410590:	mov    (%rax),%rsi
  410593:	callq  40ef21 <setString>
  410598:	mov    $0x1,%r12d
  41059e:	jmpq   40f6d3 <TIFFSetField1+0x752>
  4105a3:	mov    0x8(%r12),%rax
  4105a8:	lea    0x8(%rax),%rdx
  4105ac:	mov    %rdx,0x8(%r12)
  4105b1:	jmp    410589 <TIFFSetField1+0x1608>
  4105b3:	mov    $0x1,%r12d
  4105b9:	jmpq   40f6d3 <TIFFSetField1+0x752>
  4105be:	mov    $0x1,%r12d
  4105c4:	jmpq   40f6d3 <TIFFSetField1+0x752>
  4105c9:	mov    $0x0,%r13d
  4105cf:	jmpq   40f0c6 <TIFFSetField1+0x145>
  4105d4:	mov    $0x0,%r13d
  4105da:	jmpq   40f0c6 <TIFFSetField1+0x145>

00000000004105df <TIFFSetField>:
  4105df:	push   %r12
  4105e1:	push   %rbp
  4105e2:	push   %rbx
  4105e3:	sub    $0xd0,%rsp
  4105ea:	mov    %rdi,%r12
  4105ed:	mov    %esi,%ebx
  4105ef:	mov    %rdx,0x30(%rsp)
  4105f4:	mov    %rcx,0x38(%rsp)
  4105f9:	mov    %r8,0x40(%rsp)
  4105fe:	mov    %r9,0x48(%rsp)
  410603:	test   %al,%al
  410605:	je     41063e <TIFFSetField+0x5f>
  410607:	movaps %xmm0,0x50(%rsp)
  41060c:	movaps %xmm1,0x60(%rsp)
  410611:	movaps %xmm2,0x70(%rsp)
  410616:	movaps %xmm3,0x80(%rsp)
  41061e:	movaps %xmm4,0x90(%rsp)
  410626:	movaps %xmm5,0xa0(%rsp)
  41062e:	movaps %xmm6,0xb0(%rsp)
  410636:	movaps %xmm7,0xc0(%rsp)
  41063e:	mov    %ebx,%esi
  410640:	mov    %r12,%rdi
  410643:	mov    $0x0,%eax
  410648:	callq  40db8b <OkToChangeTag>
  41064d:	mov    %eax,%ebp
  41064f:	test   %eax,%eax
  410651:	jne    410683 <TIFFSetField+0xa4>
  410653:	movzwl %bx,%edi
  410656:	mov    $0x0,%esi
  41065b:	callq  410e60 <TIFFFindFieldInfo>
  410660:	test   %rax,%rax
  410663:	je     4106c0 <TIFFSetField+0xe1>
  410665:	mov    0x10(%rax),%rcx
  410669:	mov    (%r12),%rdx
  41066d:	mov    $0x419a68,%esi
  410672:	mov    $0x419b08,%edi
  410677:	mov    $0x0,%eax
  41067c:	callq  412a93 <TIFFError>
  410681:	jmp    4106c0 <TIFFSetField+0xe1>
  410683:	movl   $0x10,0x8(%rsp)
  41068b:	movl   $0x30,0xc(%rsp)
  410693:	lea    0xf0(%rsp),%rax
  41069b:	mov    %rax,0x10(%rsp)
  4106a0:	lea    0x20(%rsp),%rax
  4106a5:	mov    %rax,0x18(%rsp)
  4106aa:	lea    0x8(%rsp),%rdx
  4106af:	mov    %ebx,%esi
  4106b1:	mov    %r12,%rdi
  4106b4:	mov    $0x0,%eax
  4106b9:	callq  40ef81 <TIFFSetField1>
  4106be:	mov    %eax,%ebp
  4106c0:	mov    %ebp,%eax
  4106c2:	add    $0xd0,%rsp
  4106c9:	pop    %rbx
  4106ca:	pop    %rbp
  4106cb:	pop    %r12
  4106cd:	retq   

00000000004106ce <TIFFVSetField>:
  4106ce:	push   %r13
  4106d0:	push   %r12
  4106d2:	push   %rbp
  4106d3:	push   %rbx
  4106d4:	sub    $0x8,%rsp
  4106d8:	mov    %rdi,%r12
  4106db:	mov    %esi,%ebx
  4106dd:	mov    %rdx,%r13
  4106e0:	mov    $0x0,%eax
  4106e5:	callq  40db8b <OkToChangeTag>
  4106ea:	test   %eax,%eax
  4106ec:	jne    410720 <TIFFVSetField+0x52>
  4106ee:	mov    %eax,%ebp
  4106f0:	movzwl %bx,%edi
  4106f3:	mov    $0x0,%esi
  4106f8:	callq  410e60 <TIFFFindFieldInfo>
  4106fd:	test   %rax,%rax
  410700:	je     410734 <TIFFVSetField+0x66>
  410702:	mov    0x10(%rax),%rcx
  410706:	mov    (%r12),%rdx
  41070a:	mov    $0x419a68,%esi
  41070f:	mov    $0x419b15,%edi
  410714:	mov    $0x0,%eax
  410719:	callq  412a93 <TIFFError>
  41071e:	jmp    410734 <TIFFVSetField+0x66>
  410720:	mov    %r13,%rdx
  410723:	mov    %ebx,%esi
  410725:	mov    %r12,%rdi
  410728:	mov    $0x0,%eax
  41072d:	callq  40ef81 <TIFFSetField1>
  410732:	mov    %eax,%ebp
  410734:	mov    %ebp,%eax
  410736:	add    $0x8,%rsp
  41073a:	pop    %rbx
  41073b:	pop    %rbp
  41073c:	pop    %r12
  41073e:	pop    %r13
  410740:	retq   

0000000000410741 <TIFFGetField>:
  410741:	push   %rbp
  410742:	push   %rbx
  410743:	sub    $0xd8,%rsp
  41074a:	mov    %rdi,%rbp
  41074d:	mov    %esi,%ebx
  41074f:	mov    %rdx,0x30(%rsp)
  410754:	mov    %rcx,0x38(%rsp)
  410759:	mov    %r8,0x40(%rsp)
  41075e:	mov    %r9,0x48(%rsp)
  410763:	test   %al,%al
  410765:	je     41079e <TIFFGetField+0x5d>
  410767:	movaps %xmm0,0x50(%rsp)
  41076c:	movaps %xmm1,0x60(%rsp)
  410771:	movaps %xmm2,0x70(%rsp)
  410776:	movaps %xmm3,0x80(%rsp)
  41077e:	movaps %xmm4,0x90(%rsp)
  410786:	movaps %xmm5,0xa0(%rsp)
  41078e:	movaps %xmm6,0xb0(%rsp)
  410796:	movaps %xmm7,0xc0(%rsp)
  41079e:	movzwl %bx,%edi
  4107a1:	mov    $0x0,%esi
  4107a6:	callq  410e60 <TIFFFindFieldInfo>
  4107ab:	test   %rax,%rax
  4107ae:	je     41082c <TIFFGetField+0xeb>
  4107b0:	movzwl 0xc(%rax),%ecx
  4107b4:	mov    $0x0,%eax
  4107b9:	cmp    $0xffff,%cx
  4107bd:	je     4107df <TIFFGetField+0x9e>
  4107bf:	mov    %ecx,%esi
  4107c1:	shr    $0x5,%si
  4107c5:	and    $0x7ff,%esi
  4107cb:	mov    $0x1,%eax
  4107d0:	shl    %cl,%eax
  4107d2:	mov    %eax,%edx
  4107d4:	mov    $0x0,%eax
  4107d9:	test   %edx,0x20(%rbp,%rsi,8)
  4107dd:	jne    4107e9 <TIFFGetField+0xa8>
  4107df:	add    $0xd8,%rsp
  4107e6:	pop    %rbx
  4107e7:	pop    %rbp
  4107e8:	retq   
  4107e9:	movl   $0x10,0x8(%rsp)
  4107f1:	movl   $0x30,0xc(%rsp)
  4107f9:	lea    0xf0(%rsp),%rax
  410801:	mov    %rax,0x10(%rsp)
  410806:	lea    0x20(%rsp),%rax
  41080b:	mov    %rax,0x18(%rsp)
  410810:	lea    0x20(%rbp),%rdi
  410814:	lea    0x8(%rsp),%rdx
  410819:	mov    %ebx,%esi
  41081b:	mov    $0x0,%eax
  410820:	callq  40dbce <TIFFGetField1>
  410825:	mov    $0x1,%eax
  41082a:	jmp    4107df <TIFFGetField+0x9e>
  41082c:	mov    %ebx,%edx
  41082e:	mov    $0x419b23,%esi
  410833:	mov    $0x419b3b,%edi
  410838:	mov    $0x0,%eax
  41083d:	callq  412a93 <TIFFError>
  410842:	mov    $0x0,%eax
  410847:	jmp    4107df <TIFFGetField+0x9e>

0000000000410849 <TIFFVGetField>:
  410849:	push   %r12
  41084b:	push   %rbp
  41084c:	push   %rbx
  41084d:	mov    %rdi,%rbp
  410850:	mov    %esi,%ebx
  410852:	mov    %rdx,%r12
  410855:	movzwl %si,%edi
  410858:	mov    $0x0,%esi
  41085d:	callq  410e60 <TIFFFindFieldInfo>
  410862:	test   %rax,%rax
  410865:	je     4108b0 <TIFFVGetField+0x67>
  410867:	movzwl 0xc(%rax),%ecx
  41086b:	mov    $0x0,%eax
  410870:	cmp    $0xffff,%cx
  410874:	je     410896 <TIFFVGetField+0x4d>
  410876:	mov    %ecx,%esi
  410878:	shr    $0x5,%si
  41087c:	and    $0x7ff,%esi
  410882:	mov    $0x1,%eax
  410887:	shl    %cl,%eax
  410889:	mov    %eax,%edx
  41088b:	mov    $0x0,%eax
  410890:	test   %edx,0x20(%rbp,%rsi,8)
  410894:	jne    41089b <TIFFVGetField+0x52>
  410896:	pop    %rbx
  410897:	pop    %rbp
  410898:	pop    %r12
  41089a:	retq   
  41089b:	lea    0x20(%rbp),%rdi
  41089f:	mov    %r12,%rdx
  4108a2:	mov    %ebx,%esi
  4108a4:	callq  40dbce <TIFFGetField1>
  4108a9:	mov    $0x1,%eax
  4108ae:	jmp    410896 <TIFFVGetField+0x4d>
  4108b0:	mov    %ebx,%edx
  4108b2:	mov    $0x419b23,%esi
  4108b7:	mov    $0x419b3b,%edi
  4108bc:	mov    $0x0,%eax
  4108c1:	callq  412a93 <TIFFError>
  4108c6:	mov    $0x0,%eax
  4108cb:	jmp    410896 <TIFFVGetField+0x4d>

00000000004108cd <_TIFFgetfield>:
  4108cd:	sub    $0xd8,%rsp
  4108d4:	mov    %rdx,0x30(%rsp)
  4108d9:	mov    %rcx,0x38(%rsp)
  4108de:	mov    %r8,0x40(%rsp)
  4108e3:	mov    %r9,0x48(%rsp)
  4108e8:	test   %al,%al
  4108ea:	je     410923 <_TIFFgetfield+0x56>
  4108ec:	movaps %xmm0,0x50(%rsp)
  4108f1:	movaps %xmm1,0x60(%rsp)
  4108f6:	movaps %xmm2,0x70(%rsp)
  4108fb:	movaps %xmm3,0x80(%rsp)
  410903:	movaps %xmm4,0x90(%rsp)
  41090b:	movaps %xmm5,0xa0(%rsp)
  410913:	movaps %xmm6,0xb0(%rsp)
  41091b:	movaps %xmm7,0xc0(%rsp)
  410923:	movl   $0x10,0x8(%rsp)
  41092b:	movl   $0x30,0xc(%rsp)
  410933:	lea    0xe0(%rsp),%rax
  41093b:	mov    %rax,0x10(%rsp)
  410940:	lea    0x20(%rsp),%rax
  410945:	mov    %rax,0x18(%rsp)
  41094a:	lea    0x8(%rsp),%rdx
  41094f:	mov    $0x0,%eax
  410954:	callq  40dbce <TIFFGetField1>
  410959:	add    $0xd8,%rsp
  410960:	retq   

0000000000410961 <TIFFFreeDirectory>:
  410961:	push   %rbx
  410962:	mov    %rdi,%rbx
  410965:	mov    0xd0(%rdi),%rdi
  41096c:	test   %rdi,%rdi
  41096f:	je     410981 <TIFFFreeDirectory+0x20>
  410971:	callq  4010b0 <free@plt>
  410976:	movq   $0x0,0xd0(%rbx)
  410981:	mov    0xd8(%rbx),%rdi
  410988:	test   %rdi,%rdi
  41098b:	je     41099d <TIFFFreeDirectory+0x3c>
  41098d:	callq  4010b0 <free@plt>
  410992:	movq   $0x0,0xd8(%rbx)
  41099d:	mov    0xe0(%rbx),%rdi
  4109a4:	test   %rdi,%rdi
  4109a7:	je     4109b9 <TIFFFreeDirectory+0x58>
  4109a9:	callq  4010b0 <free@plt>
  4109ae:	movq   $0x0,0xe0(%rbx)
  4109b9:	mov    0xf0(%rbx),%rdi
  4109c0:	test   %rdi,%rdi
  4109c3:	je     4109d5 <TIFFFreeDirectory+0x74>
  4109c5:	callq  4010b0 <free@plt>
  4109ca:	movq   $0x0,0xf0(%rbx)
  4109d5:	mov    0xf8(%rbx),%rdi
  4109dc:	test   %rdi,%rdi
  4109df:	je     4109f1 <TIFFFreeDirectory+0x90>
  4109e1:	callq  4010b0 <free@plt>
  4109e6:	movq   $0x0,0xf8(%rbx)
  4109f1:	mov    0x100(%rbx),%rdi
  4109f8:	test   %rdi,%rdi
  4109fb:	je     410a0d <TIFFFreeDirectory+0xac>
  4109fd:	callq  4010b0 <free@plt>
  410a02:	movq   $0x0,0x100(%rbx)
  410a0d:	mov    0x108(%rbx),%rdi
  410a14:	test   %rdi,%rdi
  410a17:	je     410a29 <TIFFFreeDirectory+0xc8>
  410a19:	callq  4010b0 <free@plt>
  410a1e:	movq   $0x0,0x108(%rbx)
  410a29:	mov    0x110(%rbx),%rdi
  410a30:	test   %rdi,%rdi
  410a33:	je     410a45 <TIFFFreeDirectory+0xe4>
  410a35:	callq  4010b0 <free@plt>
  410a3a:	movq   $0x0,0x110(%rbx)
  410a45:	mov    0x118(%rbx),%rdi
  410a4c:	test   %rdi,%rdi
  410a4f:	je     410a61 <TIFFFreeDirectory+0x100>
  410a51:	callq  4010b0 <free@plt>
  410a56:	movq   $0x0,0x118(%rbx)
  410a61:	mov    0x120(%rbx),%rdi
  410a68:	test   %rdi,%rdi
  410a6b:	je     410a7d <TIFFFreeDirectory+0x11c>
  410a6d:	callq  4010b0 <free@plt>
  410a72:	movq   $0x0,0x120(%rbx)
  410a7d:	mov    0x128(%rbx),%rdi
  410a84:	test   %rdi,%rdi
  410a87:	je     410a99 <TIFFFreeDirectory+0x138>
  410a89:	callq  4010b0 <free@plt>
  410a8e:	movq   $0x0,0x128(%rbx)
  410a99:	mov    0x130(%rbx),%rdi
  410aa0:	test   %rdi,%rdi
  410aa3:	je     410ab5 <TIFFFreeDirectory+0x154>
  410aa5:	callq  4010b0 <free@plt>
  410aaa:	movq   $0x0,0x130(%rbx)
  410ab5:	mov    0x158(%rbx),%rdi
  410abc:	test   %rdi,%rdi
  410abf:	je     410ad1 <TIFFFreeDirectory+0x170>
  410ac1:	callq  4010b0 <free@plt>
  410ac6:	movq   $0x0,0x158(%rbx)
  410ad1:	mov    0x170(%rbx),%rdi
  410ad8:	test   %rdi,%rdi
  410adb:	je     410aed <TIFFFreeDirectory+0x18c>
  410add:	callq  4010b0 <free@plt>
  410ae2:	movq   $0x0,0x170(%rbx)
  410aed:	mov    0x178(%rbx),%rdi
  410af4:	test   %rdi,%rdi
  410af7:	je     410b09 <TIFFFreeDirectory+0x1a8>
  410af9:	callq  4010b0 <free@plt>
  410afe:	movq   $0x0,0x178(%rbx)
  410b09:	mov    0x180(%rbx),%rdi
  410b10:	test   %rdi,%rdi
  410b13:	je     410b25 <TIFFFreeDirectory+0x1c4>
  410b15:	callq  4010b0 <free@plt>
  410b1a:	movq   $0x0,0x180(%rbx)
  410b25:	mov    0x1c8(%rbx),%rdi
  410b2c:	test   %rdi,%rdi
  410b2f:	je     410b41 <TIFFFreeDirectory+0x1e0>
  410b31:	callq  4010b0 <free@plt>
  410b36:	movq   $0x0,0x1c8(%rbx)
  410b41:	mov    0x1d0(%rbx),%rdi
  410b48:	test   %rdi,%rdi
  410b4b:	je     410b5d <TIFFFreeDirectory+0x1fc>
  410b4d:	callq  4010b0 <free@plt>
  410b52:	movq   $0x0,0x1d0(%rbx)
  410b5d:	mov    0x188(%rbx),%rdi
  410b64:	test   %rdi,%rdi
  410b67:	je     410b79 <TIFFFreeDirectory+0x218>
  410b69:	callq  4010b0 <free@plt>
  410b6e:	movq   $0x0,0x188(%rbx)
  410b79:	mov    0x190(%rbx),%rdi
  410b80:	test   %rdi,%rdi
  410b83:	je     410b95 <TIFFFreeDirectory+0x234>
  410b85:	callq  4010b0 <free@plt>
  410b8a:	movq   $0x0,0x190(%rbx)
  410b95:	mov    0x198(%rbx),%rdi
  410b9c:	test   %rdi,%rdi
  410b9f:	je     410bb1 <TIFFFreeDirectory+0x250>
  410ba1:	callq  4010b0 <free@plt>
  410ba6:	movq   $0x0,0x198(%rbx)
  410bb1:	mov    0x1a0(%rbx),%rdi
  410bb8:	test   %rdi,%rdi
  410bbb:	je     410bcd <TIFFFreeDirectory+0x26c>
  410bbd:	callq  4010b0 <free@plt>
  410bc2:	movq   $0x0,0x1a0(%rbx)
  410bcd:	mov    0x1a8(%rbx),%rdi
  410bd4:	test   %rdi,%rdi
  410bd7:	je     410be9 <TIFFFreeDirectory+0x288>
  410bd9:	callq  4010b0 <free@plt>
  410bde:	movq   $0x0,0x1a8(%rbx)
  410be9:	mov    0x1b0(%rbx),%rdi
  410bf0:	test   %rdi,%rdi
  410bf3:	je     410c05 <TIFFFreeDirectory+0x2a4>
  410bf5:	callq  4010b0 <free@plt>
  410bfa:	movq   $0x0,0x1b0(%rbx)
  410c05:	mov    0x1b8(%rbx),%rdi
  410c0c:	test   %rdi,%rdi
  410c0f:	je     410c21 <TIFFFreeDirectory+0x2c0>
  410c11:	callq  4010b0 <free@plt>
  410c16:	movq   $0x0,0x1b8(%rbx)
  410c21:	mov    0x148(%rbx),%rdi
  410c28:	test   %rdi,%rdi
  410c2b:	je     410c3d <TIFFFreeDirectory+0x2dc>
  410c2d:	callq  4010b0 <free@plt>
  410c32:	movq   $0x0,0x148(%rbx)
  410c3d:	mov    0x150(%rbx),%rdi
  410c44:	test   %rdi,%rdi
  410c47:	je     410c59 <TIFFFreeDirectory+0x2f8>
  410c49:	callq  4010b0 <free@plt>
  410c4e:	movq   $0x0,0x150(%rbx)
  410c59:	pop    %rbx
  410c5a:	retq   

0000000000410c5b <TIFFDefaultDirectory>:
  410c5b:	push   %rbx
  410c5c:	mov    %rdi,%rbx
  410c5f:	lea    0x20(%rdi),%rdi
  410c63:	mov    $0x1b8,%esi
  410c68:	mov    $0x0,%eax
  410c6d:	callq  4012f0 <bzero@plt>
  410c72:	movw   $0x1,0x6c(%rbx)
  410c78:	movw   $0x1,0x62(%rbx)
  410c7e:	movw   $0x1,0x6a(%rbx)
  410c84:	movw   $0x1,0x6e(%rbx)
  410c8a:	movw   $0x1,0x70(%rbx)
  410c90:	movw   $0x1,0x72(%rbx)
  410c96:	mov    $0xffffffff,%eax
  410c9b:	mov    %rax,0x78(%rbx)
  410c9f:	mov    %rax,0x48(%rbx)
  410ca3:	mov    %rax,0x50(%rbx)
  410ca7:	movq   $0x1,0x58(%rbx)
  410caf:	movw   $0x2,0x98(%rbx)
  410cb8:	movw   $0x4,0x64(%rbx)
  410cbe:	movq   $0x1,0x40(%rbx)
  410cc6:	movw   $0x2,0x160(%rbx)
  410ccf:	movw   $0x2,0x162(%rbx)
  410cd8:	movw   $0x1,0x164(%rbx)
  410ce1:	movw   $0x1,0x1c0(%rbx)
  410cea:	mov    $0x1,%edx
  410cef:	mov    $0x103,%esi
  410cf4:	mov    %rbx,%rdi
  410cf7:	mov    $0x0,%eax
  410cfc:	callq  4105df <TIFFSetField>
  410d01:	andw   $0xfffd,0xe(%rbx)
  410d06:	mov    $0x1,%eax
  410d0b:	pop    %rbx
  410d0c:	retq   

0000000000410d0d <TIFFSetDirectory>:
  410d0d:	push   %r12
  410d0f:	push   %rbp
  410d10:	push   %rbx
  410d11:	sub    $0x10,%rsp
  410d15:	mov    %rdi,%rbx
  410d18:	mov    %esi,%r12d
  410d1b:	mov    0x1e0(%rdi),%rsi
  410d22:	mov    %rsi,(%rsp)
  410d26:	test   %r12d,%r12d
  410d29:	jle    410e3e <TIFFSetDirectory+0x131>
  410d2f:	test   %rsi,%rsi
  410d32:	je     410e3e <TIFFSetDirectory+0x131>
  410d38:	mov    %r12d,%ebp
  410d3b:	jmp    410da4 <TIFFSetDirectory+0x97>
  410d3d:	mov    (%rbx),%rdx
  410d40:	mov    $0x419a98,%esi
  410d45:	mov    $0x61f1b0,%edi
  410d4a:	mov    $0x0,%eax
  410d4f:	callq  412a93 <TIFFError>
  410d54:	mov    $0x0,%eax
  410d59:	add    $0x10,%rsp
  410d5d:	pop    %rbx
  410d5e:	pop    %rbp
  410d5f:	pop    %r12
  410d61:	retq   
  410d62:	lea    0xe(%rsp),%rdi
  410d67:	callq  413028 <TIFFSwabShort>
  410d6c:	jmp    410de8 <TIFFSetDirectory+0xdb>
  410d6e:	mov    (%rbx),%rdx
  410d71:	mov    $0x419ac0,%esi
  410d76:	mov    $0x61f1b0,%edi
  410d7b:	mov    $0x0,%eax
  410d80:	callq  412a93 <TIFFError>
  410d85:	mov    $0x0,%eax
  410d8a:	jmp    410d59 <TIFFSetDirectory+0x4c>
  410d8c:	sub    $0x1,%ebp
  410d8f:	mov    (%rsp),%rsi
  410d93:	test   %ebp,%ebp
  410d95:	jle    410e41 <TIFFSetDirectory+0x134>
  410d9b:	test   %rsi,%rsi
  410d9e:	je     410e41 <TIFFSetDirectory+0x134>
  410da4:	movswl 0x8(%rbx),%edi
  410da8:	mov    $0x0,%edx
  410dad:	mov    $0x0,%eax
  410db2:	callq  401190 <lseek@plt>
  410db7:	cmp    (%rsp),%rax
  410dbb:	jne    410d3d <TIFFSetDirectory+0x30>
  410dbd:	movswl 0x8(%rbx),%edi
  410dc1:	mov    $0x2,%edx
  410dc6:	lea    0xe(%rsp),%rsi
  410dcb:	mov    $0x0,%eax
  410dd0:	callq  401200 <read@plt>
  410dd5:	cmp    $0x2,%eax
  410dd8:	jne    410d3d <TIFFSetDirectory+0x30>
  410dde:	testb  $0x10,0xe(%rbx)
  410de2:	jne    410d62 <TIFFSetDirectory+0x55>
  410de8:	movzwl 0xe(%rsp),%eax
  410ded:	lea    (%rax,%rax,2),%rsi
  410df1:	shl    $0x3,%rsi
  410df5:	movswl 0x8(%rbx),%edi
  410df9:	mov    $0x1,%edx
  410dfe:	mov    $0x0,%eax
  410e03:	callq  401190 <lseek@plt>
  410e08:	movswl 0x8(%rbx),%edi
  410e0c:	mov    $0x8,%edx
  410e11:	mov    %rsp,%rsi
  410e14:	mov    $0x0,%eax
  410e19:	callq  401200 <read@plt>
  410e1e:	cmp    $0x8,%eax
  410e21:	jne    410d6e <TIFFSetDirectory+0x61>
  410e27:	testb  $0x10,0xe(%rbx)
  410e2b:	je     410d8c <TIFFSetDirectory+0x7f>
  410e31:	mov    %rsp,%rdi
  410e34:	callq  413035 <TIFFSwabLong>
  410e39:	jmpq   410d8c <TIFFSetDirectory+0x7f>
  410e3e:	mov    %r12d,%ebp
  410e41:	mov    %rsi,0x18(%rbx)
  410e45:	sub    %ebp,%r12d
  410e48:	sub    $0x1,%r12d
  410e4c:	mov    %r12d,0x200(%rbx)
  410e53:	mov    %rbx,%rdi
  410e56:	callq  411b1c <TIFFReadDirectory>
  410e5b:	jmpq   410d59 <TIFFSetDirectory+0x4c>

0000000000410e60 <TIFFFindFieldInfo>:
  410e60:	mov    %edi,%ecx
  410e62:	mov    0x231347(%rip),%rax        # 6421b0 <last.2202>
  410e69:	test   %rax,%rax
  410e6c:	je     410e73 <TIFFFindFieldInfo+0x13>
  410e6e:	cmp    %di,(%rax)
  410e71:	je     410e8a <TIFFFindFieldInfo+0x2a>
  410e73:	movzwl 0x20e3a6(%rip),%edx        # 61f220 <tiffFieldInfo>
  410e7a:	mov    $0x61f220,%eax
  410e7f:	test   %dx,%dx
  410e82:	jne    410ea1 <TIFFFindFieldInfo+0x41>
  410e84:	mov    $0x0,%eax
  410e89:	retq   
  410e8a:	test   %esi,%esi
  410e8c:	je     410ebc <TIFFFindFieldInfo+0x5c>
  410e8e:	cmp    %esi,0x8(%rax)
  410e91:	jne    410e73 <TIFFFindFieldInfo+0x13>
  410e93:	repz retq 
  410e95:	add    $0x18,%rax
  410e99:	movzwl (%rax),%edx
  410e9c:	test   %dx,%dx
  410e9f:	je     410eb7 <TIFFFindFieldInfo+0x57>
  410ea1:	cmp    %dx,%cx
  410ea4:	jne    410e95 <TIFFFindFieldInfo+0x35>
  410ea6:	test   %esi,%esi
  410ea8:	je     410eaf <TIFFFindFieldInfo+0x4f>
  410eaa:	cmp    %esi,0x8(%rax)
  410ead:	jne    410e95 <TIFFFindFieldInfo+0x35>
  410eaf:	mov    %rax,0x2312fa(%rip)        # 6421b0 <last.2202>
  410eb6:	retq   
  410eb7:	mov    $0x0,%eax
  410ebc:	repz retq 

0000000000410ebe <TIFFFieldWithTag>:
  410ebe:	push   %rbx
  410ebf:	movzwl %di,%ebx
  410ec2:	mov    $0x0,%esi
  410ec7:	mov    %ebx,%edi
  410ec9:	callq  410e60 <TIFFFindFieldInfo>
  410ece:	test   %rax,%rax
  410ed1:	je     410ed5 <TIFFFieldWithTag+0x17>
  410ed3:	pop    %rbx
  410ed4:	retq   
  410ed5:	mov    %ebx,%edx
  410ed7:	mov    $0x419ba0,%esi
  410edc:	mov    $0x419bc1,%edi
  410ee1:	callq  412a93 <TIFFError>
  410ee6:	mov    $0xffffffff,%edi
  410eeb:	callq  401340 <exit@plt>

0000000000410ef0 <MissingRequired>:
  410ef0:	sub    $0x8,%rsp
  410ef4:	mov    %rsi,%rdx
  410ef7:	mov    $0x419fa8,%esi
  410efc:	mov    (%rdi),%rdi
  410eff:	mov    $0x0,%eax
  410f04:	callq  412a93 <TIFFError>
  410f09:	add    $0x8,%rsp
  410f0d:	retq   

0000000000410f0e <CheckDirCount>:
  410f0e:	push   %r12
  410f10:	push   %rbp
  410f11:	push   %rbx
  410f12:	mov    0x8(%rsi),%rbp
  410f16:	mov    $0x1,%eax
  410f1b:	cmp    %rdx,%rbp
  410f1e:	je     410f50 <CheckDirCount+0x42>
  410f20:	mov    %rdx,%rbx
  410f23:	mov    %rdi,%r12
  410f26:	movzwl (%rsi),%edi
  410f29:	callq  410ebe <TIFFFieldWithTag>
  410f2e:	mov    0x10(%rax),%rdx
  410f32:	mov    %rbx,%r8
  410f35:	mov    %rbp,%rcx
  410f38:	mov    $0x419fd8,%esi
  410f3d:	mov    (%r12),%rdi
  410f41:	mov    $0x0,%eax
  410f46:	callq  413526 <TIFFWarning>
  410f4b:	mov    $0x0,%eax
  410f50:	pop    %rbx
  410f51:	pop    %rbp
  410f52:	pop    %r12
  410f54:	retq   

0000000000410f55 <TIFFFetchData>:
  410f55:	push   %r13
  410f57:	push   %r12
  410f59:	push   %rbp
  410f5a:	push   %rbx
  410f5b:	sub    $0x8,%rsp
  410f5f:	mov    %rdi,%r12
  410f62:	mov    %rsi,%rbp
  410f65:	mov    %rdx,%r13
  410f68:	movzwl 0x2(%rsi),%eax
  410f6c:	mov    0x8(%rsi),%rbx
  410f70:	imul   0x61f1e0(,%rax,4),%ebx
  410f78:	testb  $0x1,0xf(%rdi)
  410f7c:	je     410fc4 <TIFFFetchData+0x6f>
  410f7e:	mov    0x10(%rsi),%rdi
  410f82:	movslq %ebx,%rax
  410f85:	add    %rdi,%rax
  410f88:	cmp    0x2c0(%r12),%rax
  410f90:	jbe    410ffc <TIFFFetchData+0xa7>
  410f92:	movzwl 0x0(%rbp),%edi
  410f96:	callq  410ebe <TIFFFieldWithTag>
  410f9b:	mov    0x10(%rax),%rdx
  410f9f:	mov    $0x41a020,%esi
  410fa4:	mov    (%r12),%rdi
  410fa8:	mov    $0x0,%eax
  410fad:	callq  412a93 <TIFFError>
  410fb2:	mov    $0x0,%ebx
  410fb7:	mov    %ebx,%eax
  410fb9:	add    $0x8,%rsp
  410fbd:	pop    %rbx
  410fbe:	pop    %rbp
  410fbf:	pop    %r12
  410fc1:	pop    %r13
  410fc3:	retq   
  410fc4:	mov    0x10(%rsi),%rsi
  410fc8:	movswl 0x8(%rdi),%edi
  410fcc:	mov    $0x0,%edx
  410fd1:	mov    $0x0,%eax
  410fd6:	callq  401190 <lseek@plt>
  410fdb:	cmp    0x10(%rbp),%rax
  410fdf:	jne    410f92 <TIFFFetchData+0x3d>
  410fe1:	movswl 0x8(%r12),%edi
  410fe7:	mov    %ebx,%edx
  410fe9:	mov    %r13,%rsi
  410fec:	mov    $0x0,%eax
  410ff1:	callq  401200 <read@plt>
  410ff6:	cmp    %ebx,%eax
  410ff8:	jne    410f92 <TIFFFetchData+0x3d>
  410ffa:	jmp    411013 <TIFFFetchData+0xbe>
  410ffc:	add    0x2b8(%r12),%rdi
  411004:	mov    %ebx,%edx
  411006:	mov    %r13,%rsi
  411009:	mov    $0x0,%eax
  41100e:	callq  4012d0 <bcopy@plt>
  411013:	testb  $0x10,0xe(%r12)
  411019:	je     410fb7 <TIFFFetchData+0x62>
  41101b:	movzwl 0x2(%rbp),%eax
  41101f:	sub    $0x3,%eax
  411022:	cmp    $0x8,%ax
  411026:	ja     410fb7 <TIFFFetchData+0x62>
  411028:	movzwl %ax,%eax
  41102b:	jmpq   *0x41a2b8(,%rax,8)
  411032:	mov    0x8(%rbp),%rsi
  411036:	mov    %r13,%rdi
  411039:	callq  413050 <TIFFSwabArrayOfShort>
  41103e:	jmpq   410fb7 <TIFFFetchData+0x62>
  411043:	mov    0x8(%rbp),%rsi
  411047:	mov    %r13,%rdi
  41104a:	callq  413073 <TIFFSwabArrayOfLong>
  41104f:	jmpq   410fb7 <TIFFFetchData+0x62>
  411054:	mov    0x8(%rbp),%rsi
  411058:	add    %esi,%esi
  41105a:	mov    %r13,%rdi
  41105d:	callq  413073 <TIFFSwabArrayOfLong>
  411062:	jmpq   410fb7 <TIFFFetchData+0x62>

0000000000411067 <TIFFFetchShortArray>:
  411067:	mov    0x8(%rsi),%rax
  41106b:	cmp    $0x2,%rax
  41106f:	ja     4110c6 <TIFFFetchShortArray+0x5f>
  411071:	cmpw   $0x4d4d,0x1d8(%rdi)
  41107a:	je     4110a1 <TIFFFetchShortArray+0x3a>
  41107c:	cmp    $0x1,%rax
  411080:	je     411094 <TIFFFetchShortArray+0x2d>
  411082:	cmp    $0x2,%rax
  411086:	jne    4110da <TIFFFetchShortArray+0x73>
  411088:	mov    0x10(%rsi),%rax
  41108c:	shr    $0x10,%rax
  411090:	mov    %ax,0x2(%rdx)
  411094:	mov    0x10(%rsi),%rax
  411098:	mov    %ax,(%rdx)
  41109b:	mov    $0x1,%eax
  4110a0:	retq   
  4110a1:	cmp    $0x1,%rax
  4110a5:	je     4110b5 <TIFFFetchShortArray+0x4e>
  4110a7:	cmp    $0x2,%rax
  4110ab:	jne    4110d4 <TIFFFetchShortArray+0x6d>
  4110ad:	mov    0x10(%rsi),%rax
  4110b1:	mov    %ax,0x2(%rdx)
  4110b5:	mov    0x10(%rsi),%rax
  4110b9:	shr    $0x10,%rax
  4110bd:	mov    %ax,(%rdx)
  4110c0:	mov    $0x1,%eax
  4110c5:	retq   
  4110c6:	sub    $0x8,%rsp
  4110ca:	callq  410f55 <TIFFFetchData>
  4110cf:	add    $0x8,%rsp
  4110d3:	retq   
  4110d4:	mov    $0x1,%eax
  4110d9:	retq   
  4110da:	mov    $0x1,%eax
  4110df:	retq   

00000000004110e0 <TIFFFetchString>:
  4110e0:	push   %rbp
  4110e1:	push   %rbx
  4110e2:	sub    $0x18,%rsp
  4110e6:	mov    %rsi,%rbx
  4110e9:	mov    %rdx,%rbp
  4110ec:	cmpq   $0x4,0x8(%rsi)
  4110f1:	ja     411130 <TIFFFetchString+0x50>
  4110f3:	mov    0x10(%rsi),%rax
  4110f7:	mov    %rax,0x8(%rsp)
  4110fc:	testb  $0x10,0xe(%rdi)
  411100:	jne    411124 <TIFFFetchString+0x44>
  411102:	mov    0x8(%rbx),%rdx
  411106:	mov    %rbp,%rsi
  411109:	lea    0x8(%rsp),%rdi
  41110e:	mov    $0x0,%eax
  411113:	callq  4012d0 <bcopy@plt>
  411118:	mov    $0x1,%eax
  41111d:	add    $0x18,%rsp
  411121:	pop    %rbx
  411122:	pop    %rbp
  411123:	retq   
  411124:	lea    0x8(%rsp),%rdi
  411129:	callq  413035 <TIFFSwabLong>
  41112e:	jmp    411102 <TIFFFetchString+0x22>
  411130:	callq  410f55 <TIFFFetchData>
  411135:	jmp    41111d <TIFFFetchString+0x3d>

0000000000411137 <cvtRational>:
  411137:	test   %rcx,%rcx
  41113a:	je     411164 <cvtRational+0x2d>
  41113c:	cmpw   $0x5,0x2(%rsi)
  411141:	je     41119e <cvtRational+0x67>
  411143:	pxor   %xmm0,%xmm0
  411147:	cvtsi2ss %rdx,%xmm0
  41114c:	pxor   %xmm1,%xmm1
  411150:	cvtsi2ss %rcx,%xmm1
  411155:	divss  %xmm1,%xmm0
  411159:	movss  %xmm0,(%r8)
  41115e:	mov    $0x1,%eax
  411163:	retq   
  411164:	push   %rbp
  411165:	push   %rbx
  411166:	sub    $0x8,%rsp
  41116a:	mov    %rdx,%rbx
  41116d:	mov    %rdi,%rbp
  411170:	movzwl (%rsi),%edi
  411173:	callq  410ebe <TIFFFieldWithTag>
  411178:	mov    0x10(%rax),%rdx
  41117c:	mov    %rbx,%rcx
  41117f:	mov    $0x41a048,%esi
  411184:	mov    0x0(%rbp),%rdi
  411188:	mov    $0x0,%eax
  41118d:	callq  412a93 <TIFFError>
  411192:	mov    $0x0,%eax
  411197:	add    $0x8,%rsp
  41119b:	pop    %rbx
  41119c:	pop    %rbp
  41119d:	retq   
  41119e:	test   %rdx,%rdx
  4111a1:	js     4111c9 <cvtRational+0x92>
  4111a3:	pxor   %xmm0,%xmm0
  4111a7:	cvtsi2ss %rdx,%xmm0
  4111ac:	test   %rcx,%rcx
  4111af:	js     4111e4 <cvtRational+0xad>
  4111b1:	pxor   %xmm1,%xmm1
  4111b5:	cvtsi2ss %rcx,%xmm1
  4111ba:	divss  %xmm1,%xmm0
  4111be:	movss  %xmm0,(%r8)
  4111c3:	mov    $0x1,%eax
  4111c8:	retq   
  4111c9:	mov    %rdx,%rax
  4111cc:	shr    %rax
  4111cf:	and    $0x1,%edx
  4111d2:	or     %rdx,%rax
  4111d5:	pxor   %xmm0,%xmm0
  4111d9:	cvtsi2ss %rax,%xmm0
  4111de:	addss  %xmm0,%xmm0
  4111e2:	jmp    4111ac <cvtRational+0x75>
  4111e4:	mov    %rcx,%rax
  4111e7:	shr    %rax
  4111ea:	and    $0x1,%ecx
  4111ed:	or     %rcx,%rax
  4111f0:	pxor   %xmm1,%xmm1
  4111f4:	cvtsi2ss %rax,%xmm1
  4111f9:	addss  %xmm1,%xmm1
  4111fd:	jmp    4111ba <cvtRational+0x83>

00000000004111ff <CheckMalloc>:
  4111ff:	push   %r12
  411201:	push   %rbp
  411202:	push   %rbx
  411203:	mov    %rdi,%rbp
  411206:	mov    %rdx,%r12
  411209:	mov    %esi,%edi
  41120b:	mov    $0x0,%eax
  411210:	callq  401270 <malloc@plt>
  411215:	mov    %rax,%rbx
  411218:	test   %rax,%rax
  41121b:	je     411225 <CheckMalloc+0x26>
  41121d:	mov    %rbx,%rax
  411220:	pop    %rbx
  411221:	pop    %rbp
  411222:	pop    %r12
  411224:	retq   
  411225:	mov    %r12,%rdx
  411228:	mov    $0x41a3c0,%esi
  41122d:	mov    0x0(%rbp),%rdi
  411231:	mov    $0x0,%eax
  411236:	callq  412a93 <TIFFError>
  41123b:	jmp    41121d <CheckMalloc+0x1e>

000000000041123d <TIFFFetchStripThing>:
  41123d:	push   %r15
  41123f:	push   %r14
  411241:	push   %r13
  411243:	push   %r12
  411245:	push   %rbp
  411246:	push   %rbx
  411247:	sub    $0x8,%rsp
  41124b:	mov    %rdi,%r12
  41124e:	mov    %rsi,%rbp
  411251:	mov    %rdx,%r13
  411254:	mov    %rcx,%r14
  411257:	callq  410f0e <CheckDirCount>
  41125c:	mov    %eax,%ebx
  41125e:	test   %eax,%eax
  411260:	je     41128d <TIFFFetchStripThing+0x50>
  411262:	cmpq   $0x0,(%r14)
  411266:	je     41129e <TIFFFetchStripThing+0x61>
  411268:	mov    (%r14),%r14
  41126b:	cmpw   $0x3,0x2(%rbp)
  411270:	je     4112c7 <TIFFFetchStripThing+0x8a>
  411272:	cmpq   $0x1,0x8(%rbp)
  411277:	je     41132e <TIFFFetchStripThing+0xf1>
  41127d:	mov    %r14,%rdx
  411280:	mov    %rbp,%rsi
  411283:	mov    %r12,%rdi
  411286:	callq  410f55 <TIFFFetchData>
  41128b:	mov    %eax,%ebx
  41128d:	mov    %ebx,%eax
  41128f:	add    $0x8,%rsp
  411293:	pop    %rbx
  411294:	pop    %rbp
  411295:	pop    %r12
  411297:	pop    %r13
  411299:	pop    %r14
  41129b:	pop    %r15
  41129d:	retq   
  41129e:	lea    0x0(,%r13,8),%rsi
  4112a6:	mov    $0x41a3cc,%edx
  4112ab:	mov    %r12,%rdi
  4112ae:	mov    $0x0,%eax
  4112b3:	callq  4111ff <CheckMalloc>
  4112b8:	mov    %rax,(%r14)
  4112bb:	mov    $0x0,%ebx
  4112c0:	test   %rax,%rax
  4112c3:	jne    411268 <TIFFFetchStripThing+0x2b>
  4112c5:	jmp    41128d <TIFFFetchStripThing+0x50>
  4112c7:	mov    0x8(%rbp),%rax
  4112cb:	lea    (%rax,%rax,1),%rsi
  4112cf:	mov    $0x41a3dc,%edx
  4112d4:	mov    %r12,%rdi
  4112d7:	mov    $0x0,%eax
  4112dc:	callq  4111ff <CheckMalloc>
  4112e1:	mov    %rax,%r15
  4112e4:	mov    $0x0,%ebx
  4112e9:	test   %rax,%rax
  4112ec:	je     41128d <TIFFFetchStripThing+0x50>
  4112ee:	mov    %rax,%rdx
  4112f1:	mov    %rbp,%rsi
  4112f4:	mov    %r12,%rdi
  4112f7:	callq  411067 <TIFFFetchShortArray>
  4112fc:	mov    %eax,%ebx
  4112fe:	test   %eax,%eax
  411300:	je     411321 <TIFFFetchStripThing+0xe4>
  411302:	test   %r13,%r13
  411305:	jle    411321 <TIFFFetchStripThing+0xe4>
  411307:	add    %r13,%r13
  41130a:	mov    $0x0,%eax
  41130f:	movzwl (%r15,%rax,1),%edx
  411314:	mov    %rdx,(%r14,%rax,4)
  411318:	add    $0x2,%rax
  41131c:	cmp    %rax,%r13
  41131f:	jne    41130f <TIFFFetchStripThing+0xd2>
  411321:	mov    %r15,%rdi
  411324:	callq  4010b0 <free@plt>
  411329:	jmpq   41128d <TIFFFetchStripThing+0x50>
  41132e:	mov    0x10(%rbp),%rax
  411332:	mov    %rax,(%r14)
  411335:	mov    $0x1,%ebx
  41133a:	jmpq   41128d <TIFFFetchStripThing+0x50>

000000000041133f <TIFFFetchJPEGCTables>:
  41133f:	push   %r15
  411341:	push   %r14
  411343:	push   %r13
  411345:	push   %r12
  411347:	push   %rbp
  411348:	push   %rbx
  411349:	sub    $0x48,%rsp
  41134d:	mov    %rdi,%r12
  411350:	mov    %rsi,%r13
  411353:	mov    %rdx,%r14
  411356:	cmpq   $0x1,0x8(%rsi)
  41135b:	ja     411433 <TIFFFetchJPEGCTables+0xf4>
  411361:	mov    0x10(%rsi),%rax
  411365:	mov    %rax,0x20(%rsp)
  41136a:	imul   $0x118,0x8(%r13),%rsi
  411372:	mov    $0x41a3ef,%edx
  411377:	mov    %r12,%rdi
  41137a:	mov    $0x0,%eax
  41137f:	callq  4111ff <CheckMalloc>
  411384:	mov    %rax,%rdx
  411387:	mov    %rax,(%r14)
  41138a:	mov    $0x0,%eax
  41138f:	test   %rdx,%rdx
  411392:	je     411445 <TIFFFetchJPEGCTables+0x106>
  411398:	movw   $0x1,0x2(%rsp)
  41139f:	mov    0x8(%r13),%rax
  4113a3:	lea    (%rdx,%rax,8),%rbx
  4113a7:	test   %rax,%rax
  4113aa:	je     411454 <TIFFFetchJPEGCTables+0x115>
  4113b0:	mov    $0x0,%ebp
  4113b5:	mov    (%r14),%rax
  4113b8:	mov    %rbx,(%rax,%rbp,8)
  4113bc:	mov    0x20(%rsp,%rbp,8),%rax
  4113c1:	mov    %rax,0x10(%rsp)
  4113c6:	movq   $0x10,0x8(%rsp)
  4113cf:	mov    %rbx,%rdx
  4113d2:	mov    %rsp,%rsi
  4113d5:	mov    %r12,%rdi
  4113d8:	callq  410f55 <TIFFFetchData>
  4113dd:	test   %eax,%eax
  4113df:	je     411445 <TIFFFetchJPEGCTables+0x106>
  4113e1:	mov    %rbx,%rax
  4113e4:	lea    0x10(%rbx),%rsi
  4113e8:	mov    $0x0,%edx
  4113ed:	movsbl (%rax),%ecx
  4113f0:	add    %ecx,%edx
  4113f2:	add    $0x1,%rax
  4113f6:	cmp    %rax,%rsi
  4113f9:	jne    4113ed <TIFFFetchJPEGCTables+0xae>
  4113fb:	addq   $0x10,0x10(%rsp)
  411401:	movslq %edx,%r15
  411404:	mov    %r15,0x8(%rsp)
  411409:	add    $0x10,%rbx
  41140d:	mov    %rbx,%rdx
  411410:	mov    %rsp,%rsi
  411413:	mov    %r12,%rdi
  411416:	callq  410f55 <TIFFFetchData>
  41141b:	test   %eax,%eax
  41141d:	je     411445 <TIFFFetchJPEGCTables+0x106>
  41141f:	add    %r15,%rbx
  411422:	add    $0x1,%rbp
  411426:	cmp    %rbp,0x8(%r13)
  41142a:	ja     4113b5 <TIFFFetchJPEGCTables+0x76>
  41142c:	mov    $0x1,%eax
  411431:	jmp    411445 <TIFFFetchJPEGCTables+0x106>
  411433:	lea    0x20(%rsp),%rdx
  411438:	callq  410f55 <TIFFFetchData>
  41143d:	test   %eax,%eax
  41143f:	jne    41136a <TIFFFetchJPEGCTables+0x2b>
  411445:	add    $0x48,%rsp
  411449:	pop    %rbx
  41144a:	pop    %rbp
  41144b:	pop    %r12
  41144d:	pop    %r13
  41144f:	pop    %r14
  411451:	pop    %r15
  411453:	retq   
  411454:	mov    $0x1,%eax
  411459:	jmp    411445 <TIFFFetchJPEGCTables+0x106>

000000000041145b <EstimateStripByteCounts>:
  41145b:	push   %r13
  41145d:	push   %r12
  41145f:	push   %rbp
  411460:	push   %rbx
  411461:	sub    $0x8,%rsp
  411465:	mov    %rdi,%rbp
  411468:	mov    %rsi,%rbx
  41146b:	mov    %edx,%r13d
  41146e:	mov    $0x41a406,%edx
  411473:	mov    $0x8,%esi
  411478:	mov    $0x0,%eax
  41147d:	callq  4111ff <CheckMalloc>
  411482:	mov    %rax,0x150(%rbp)
  411489:	cmpw   $0x1,0x66(%rbp)
  41148e:	jne    4114db <EstimateStripByteCounts+0x80>
  411490:	movzwl 0x62(%rbp),%edx
  411494:	movzwl 0x70(%rbp),%ecx
  411498:	imul   %ecx,%edx
  41149b:	imul   0x30(%rbp),%edx
  41149f:	add    $0x7,%edx
  4114a2:	shr    $0x3,%edx
  4114a5:	mov    %edx,%edx
  4114a7:	imul   0x38(%rbp),%rdx
  4114ac:	mov    %rdx,(%rax)
  4114af:	mov    0x20(%rbp),%rax
  4114b3:	mov    %rax,%rdx
  4114b6:	or     $0x4000000,%rdx
  4114bd:	mov    %rdx,0x20(%rbp)
  4114c1:	test   $0x20000,%eax
  4114c6:	jne    4114d0 <EstimateStripByteCounts+0x75>
  4114c8:	mov    0x38(%rbp),%rax
  4114cc:	mov    %rax,0x78(%rbp)
  4114d0:	add    $0x8,%rsp
  4114d4:	pop    %rbx
  4114d5:	pop    %rbp
  4114d6:	pop    %r12
  4114d8:	pop    %r13
  4114da:	retq   
  4114db:	mov    %r13d,%eax
  4114de:	lea    (%rax,%rax,2),%rax
  4114e2:	lea    0x1a(,%rax,8),%r12
  4114ea:	movswl 0x8(%rbp),%edi
  4114ee:	callq  40dae3 <TIFFGetFileSize>
  4114f3:	test   %r13d,%r13d
  4114f6:	jle    41152b <EstimateStripByteCounts+0xd0>
  4114f8:	lea    -0x1(%r13),%edx
  4114fc:	lea    0x3(%rdx,%rdx,2),%rdx
  411501:	lea    (%rbx,%rdx,8),%rsi
  411505:	movzwl 0x2(%rbx),%ecx
  411509:	mov    0x8(%rbx),%rdx
  41150d:	imul   0x61f1e0(,%rcx,4),%edx
  411515:	movslq %edx,%rcx
  411518:	add    %r12,%rcx
  41151b:	cmp    $0x8,%edx
  41151e:	cmova  %rcx,%r12
  411522:	add    $0x18,%rbx
  411526:	cmp    %rbx,%rsi
  411529:	jne    411505 <EstimateStripByteCounts+0xaa>
  41152b:	mov    0x150(%rbp),%rdx
  411532:	mov    %rax,%rcx
  411535:	sub    %r12,%rcx
  411538:	mov    %rcx,(%rdx)
  41153b:	mov    0x148(%rbp),%rdx
  411542:	mov    (%rdx),%rcx
  411545:	mov    0x150(%rbp),%rdx
  41154c:	mov    %rcx,%rsi
  41154f:	add    (%rdx),%rsi
  411552:	cmp    %rsi,%rax
  411555:	jae    4114af <EstimateStripByteCounts+0x54>
  41155b:	sub    %rcx,%rax
  41155e:	mov    %rax,(%rdx)
  411561:	jmpq   4114af <EstimateStripByteCounts+0x54>

0000000000411566 <TIFFFetchNormalTag>:
  411566:	push   %r15
  411568:	push   %r14
  41156a:	push   %r13
  41156c:	push   %r12
  41156e:	push   %rbp
  41156f:	push   %rbx
  411570:	sub    $0x38,%rsp
  411574:	mov    %rdi,%rbp
  411577:	mov    %rsi,%rbx
  41157a:	mov    0x8(%rsi),%rsi
  41157e:	cmp    $0x1,%rsi
  411582:	jbe    4118e4 <TIFFFetchNormalTag+0x37e>
  411588:	cmpw   $0xb,0x2(%rbx)
  41158d:	ja     4118d3 <TIFFFetchNormalTag+0x36d>
  411593:	movzwl 0x2(%rbx),%eax
  411597:	jmpq   *0x41a300(,%rax,8)
  41159e:	add    %rsi,%rsi
  4115a1:	mov    $0x61fac0,%edx
  4115a6:	mov    $0x0,%eax
  4115ab:	callq  4111ff <CheckMalloc>
  4115b0:	mov    %rax,%r12
  4115b3:	test   %rax,%rax
  4115b6:	je     411b11 <TIFFFetchNormalTag+0x5ab>
  4115bc:	mov    0x8(%rbx),%rax
  4115c0:	cmp    $0x4,%rax
  4115c4:	ja     4116de <TIFFFetchNormalTag+0x178>
  4115ca:	cmpw   $0x4d4d,0x1d8(%rbp)
  4115d3:	je     41166d <TIFFFetchNormalTag+0x107>
  4115d9:	cmp    $0x2,%rax
  4115dd:	je     411611 <TIFFFetchNormalTag+0xab>
  4115df:	cmp    $0x2,%rax
  4115e3:	jbe    4116ca <TIFFFetchNormalTag+0x164>
  4115e9:	cmp    $0x3,%rax
  4115ed:	je     411607 <TIFFFetchNormalTag+0xa1>
  4115ef:	cmp    $0x4,%rax
  4115f3:	jne    4116d4 <TIFFFetchNormalTag+0x16e>
  4115f9:	mov    0x10(%rbx),%rax
  4115fd:	shr    $0x18,%rax
  411601:	mov    %ax,0x6(%r12)
  411607:	movzbl 0x12(%rbx),%eax
  41160b:	mov    %ax,0x4(%r12)
  411611:	movzbl 0x11(%rbx),%eax
  411615:	mov    %ax,0x2(%r12)
  41161b:	movzbl 0x10(%rbx),%eax
  41161f:	mov    %ax,(%r12)
  411624:	mov    $0x1,%eax
  411629:	test   %eax,%eax
  41162b:	setne  %r13b
  41162f:	movzbl %r13b,%r13d
  411633:	test   %r13d,%r13d
  411636:	je     411653 <TIFFFetchNormalTag+0xed>
  411638:	movzwl (%rbx),%esi
  41163b:	mov    %r12,%rdx
  41163e:	mov    %rbp,%rdi
  411641:	mov    $0x0,%eax
  411646:	callq  4105df <TIFFSetField>
  41164b:	mov    %eax,%r13d
  41164e:	test   %r12,%r12
  411651:	je     41165b <TIFFFetchNormalTag+0xf5>
  411653:	mov    %r12,%rdi
  411656:	callq  4010b0 <free@plt>
  41165b:	mov    %r13d,%eax
  41165e:	add    $0x38,%rsp
  411662:	pop    %rbx
  411663:	pop    %rbp
  411664:	pop    %r12
  411666:	pop    %r13
  411668:	pop    %r14
  41166a:	pop    %r15
  41166c:	retq   
  41166d:	cmp    $0x2,%rax
  411671:	je     411699 <TIFFFetchNormalTag+0x133>
  411673:	cmp    $0x2,%rax
  411677:	jbe    4116ba <TIFFFetchNormalTag+0x154>
  411679:	cmp    $0x3,%rax
  41167d:	je     41168f <TIFFFetchNormalTag+0x129>
  41167f:	cmp    $0x4,%rax
  411683:	jne    4116c0 <TIFFFetchNormalTag+0x15a>
  411685:	movzbl 0x10(%rbx),%eax
  411689:	mov    %ax,0x6(%r12)
  41168f:	movzbl 0x11(%rbx),%eax
  411693:	mov    %ax,0x4(%r12)
  411699:	movzbl 0x12(%rbx),%eax
  41169d:	mov    %ax,0x2(%r12)
  4116a3:	mov    0x10(%rbx),%rax
  4116a7:	shr    $0x18,%rax
  4116ab:	mov    %ax,(%r12)
  4116b0:	mov    $0x1,%eax
  4116b5:	jmpq   411629 <TIFFFetchNormalTag+0xc3>
  4116ba:	cmp    $0x1,%rax
  4116be:	je     4116a3 <TIFFFetchNormalTag+0x13d>
  4116c0:	mov    $0x1,%eax
  4116c5:	jmpq   411629 <TIFFFetchNormalTag+0xc3>
  4116ca:	cmp    $0x1,%rax
  4116ce:	je     41161b <TIFFFetchNormalTag+0xb5>
  4116d4:	mov    $0x1,%eax
  4116d9:	jmpq   411629 <TIFFFetchNormalTag+0xc3>
  4116de:	mov    %r12,%rdx
  4116e1:	mov    %rbx,%rsi
  4116e4:	mov    %rbp,%rdi
  4116e7:	callq  410f55 <TIFFFetchData>
  4116ec:	jmpq   411629 <TIFFFetchNormalTag+0xc3>
  4116f1:	add    %rsi,%rsi
  4116f4:	mov    $0x61fac0,%edx
  4116f9:	mov    $0x0,%eax
  4116fe:	callq  4111ff <CheckMalloc>
  411703:	mov    %rax,%r12
  411706:	test   %rax,%rax
  411709:	je     411b11 <TIFFFetchNormalTag+0x5ab>
  41170f:	mov    %rax,%rdx
  411712:	mov    %rbx,%rsi
  411715:	mov    %rbp,%rdi
  411718:	callq  411067 <TIFFFetchShortArray>
  41171d:	test   %eax,%eax
  41171f:	setne  %r13b
  411723:	movzbl %r13b,%r13d
  411727:	jmpq   411633 <TIFFFetchNormalTag+0xcd>
  41172c:	shl    $0x3,%rsi
  411730:	mov    $0x61fac0,%edx
  411735:	mov    $0x0,%eax
  41173a:	callq  4111ff <CheckMalloc>
  41173f:	mov    %rax,%r12
  411742:	test   %rax,%rax
  411745:	je     411b11 <TIFFFetchNormalTag+0x5ab>
  41174b:	cmpq   $0x1,0x8(%rbx)
  411750:	je     41176f <TIFFFetchNormalTag+0x209>
  411752:	mov    %rax,%rdx
  411755:	mov    %rbx,%rsi
  411758:	mov    %rbp,%rdi
  41175b:	callq  410f55 <TIFFFetchData>
  411760:	test   %eax,%eax
  411762:	setne  %r13b
  411766:	movzbl %r13b,%r13d
  41176a:	jmpq   411633 <TIFFFetchNormalTag+0xcd>
  41176f:	mov    0x10(%rbx),%rax
  411773:	mov    %rax,(%r12)
  411777:	mov    $0x1,%eax
  41177c:	jmp    411760 <TIFFFetchNormalTag+0x1fa>
  41177e:	shl    $0x2,%rsi
  411782:	mov    $0x61fac0,%edx
  411787:	mov    $0x0,%eax
  41178c:	callq  4111ff <CheckMalloc>
  411791:	mov    %rax,%r12
  411794:	test   %rax,%rax
  411797:	je     411b11 <TIFFFetchNormalTag+0x5ab>
  41179d:	movzwl 0x2(%rbx),%eax
  4117a1:	movslq 0x61f1e0(,%rax,4),%rsi
  4117a9:	imul   0x8(%rbx),%rsi
  4117ae:	mov    $0x41a422,%edx
  4117b3:	mov    %rbp,%rdi
  4117b6:	mov    $0x0,%eax
  4117bb:	callq  4111ff <CheckMalloc>
  4117c0:	mov    %rax,%r13
  4117c3:	mov    %rax,0x8(%rsp)
  4117c8:	mov    $0x0,%r14d
  4117ce:	test   %rax,%rax
  4117d1:	je     411839 <TIFFFetchNormalTag+0x2d3>
  4117d3:	mov    %rax,%rdx
  4117d6:	mov    %rbx,%rsi
  4117d9:	mov    %rbp,%rdi
  4117dc:	callq  410f55 <TIFFFetchData>
  4117e1:	mov    %eax,%r14d
  4117e4:	test   %eax,%eax
  4117e6:	je     41182f <TIFFFetchNormalTag+0x2c9>
  4117e8:	cmpq   $0x0,0x8(%rbx)
  4117ed:	je     411849 <TIFFFetchNormalTag+0x2e3>
  4117ef:	mov    %r12,(%rsp)
  4117f3:	mov    $0x0,%r15d
  4117f9:	mov    0x8(%r13),%rcx
  4117fd:	mov    (%rsp),%r8
  411801:	mov    0x0(%r13),%rdx
  411805:	mov    %rbx,%rsi
  411808:	mov    %rbp,%rdi
  41180b:	mov    $0x0,%eax
  411810:	callq  411137 <cvtRational>
  411815:	mov    %eax,%r14d
  411818:	test   %eax,%eax
  41181a:	je     41182f <TIFFFetchNormalTag+0x2c9>
  41181c:	add    $0x1,%r15
  411820:	add    $0x10,%r13
  411824:	addq   $0x4,(%rsp)
  411829:	cmp    0x8(%rbx),%r15
  41182d:	jb     4117f9 <TIFFFetchNormalTag+0x293>
  41182f:	mov    0x8(%rsp),%rdi
  411834:	callq  4010b0 <free@plt>
  411839:	test   %r14d,%r14d
  41183c:	setne  %r13b
  411840:	movzbl %r13b,%r13d
  411844:	jmpq   411633 <TIFFFetchNormalTag+0xcd>
  411849:	mov    $0x0,%r14d
  41184f:	jmp    41182f <TIFFFetchNormalTag+0x2c9>
  411851:	shl    $0x2,%rsi
  411855:	mov    $0x61fac0,%edx
  41185a:	mov    $0x0,%eax
  41185f:	callq  4111ff <CheckMalloc>
  411864:	mov    %rax,%r12
  411867:	test   %rax,%rax
  41186a:	je     411b11 <TIFFFetchNormalTag+0x5ab>
  411870:	mov    %rax,%rdx
  411873:	mov    %rbx,%rsi
  411876:	mov    %rbp,%rdi
  411879:	callq  410f55 <TIFFFetchData>
  41187e:	test   %eax,%eax
  411880:	setne  %r13b
  411884:	movzbl %r13b,%r13d
  411888:	jmpq   411633 <TIFFFetchNormalTag+0xcd>
  41188d:	add    $0x1,%rsi
  411891:	mov    $0x61fac0,%edx
  411896:	mov    $0x0,%eax
  41189b:	callq  4111ff <CheckMalloc>
  4118a0:	mov    %rax,%r12
  4118a3:	test   %rax,%rax
  4118a6:	je     411b11 <TIFFFetchNormalTag+0x5ab>
  4118ac:	mov    %rax,%rdx
  4118af:	mov    %rbx,%rsi
  4118b2:	mov    %rbp,%rdi
  4118b5:	callq  4110e0 <TIFFFetchString>
  4118ba:	mov    %eax,%r13d
  4118bd:	test   %eax,%eax
  4118bf:	je     411653 <TIFFFetchNormalTag+0xed>
  4118c5:	mov    0x8(%rbx),%rax
  4118c9:	movb   $0x0,(%r12,%rax,1)
  4118ce:	jmpq   411638 <TIFFFetchNormalTag+0xd2>
  4118d3:	mov    $0x0,%r12d
  4118d9:	mov    $0x0,%r13d
  4118df:	jmpq   41164e <TIFFFetchNormalTag+0xe8>
  4118e4:	mov    $0x1,%edx
  4118e9:	mov    %rbx,%rsi
  4118ec:	callq  410f0e <CheckDirCount>
  4118f1:	mov    %eax,%r13d
  4118f4:	test   %eax,%eax
  4118f6:	je     41165b <TIFFFetchNormalTag+0xf5>
  4118fc:	movzwl 0x2(%rbx),%eax
  411900:	cmp    $0xb,%ax
  411904:	ja     411b06 <TIFFFetchNormalTag+0x5a0>
  41190a:	movzwl %ax,%edx
  41190d:	jmpq   *0x41a360(,%rdx,8)
  411914:	cmpw   $0x4d4d,0x1d8(%rbp)
  41191d:	je     411948 <TIFFFetchNormalTag+0x3e2>
  41191f:	movzwl %ax,%eax
  411922:	mov    0x1f0(%rbp),%rcx
  411929:	mov    0x10(%rbx),%rdx
  41192d:	and    (%rcx,%rax,8),%edx
  411930:	movzwl (%rbx),%esi
  411933:	mov    %rbp,%rdi
  411936:	mov    $0x0,%eax
  41193b:	callq  4105df <TIFFSetField>
  411940:	mov    %eax,%r13d
  411943:	jmpq   41165b <TIFFFetchNormalTag+0xf5>
  411948:	movzwl %ax,%eax
  41194b:	mov    0x1e8(%rbp),%rdx
  411952:	mov    (%rdx,%rax,4),%ecx
  411955:	mov    0x10(%rbx),%rdx
  411959:	shr    %cl,%rdx
  41195c:	mov    0x1f0(%rbp),%rcx
  411963:	and    (%rcx,%rax,8),%edx
  411966:	jmp    411930 <TIFFFetchNormalTag+0x3ca>
  411968:	cmpw   $0x4d4d,0x1d8(%rbp)
  411971:	je     41199d <TIFFFetchNormalTag+0x437>
  411973:	movzwl %ax,%eax
  411976:	mov    0x1f0(%rbp),%rdx
  41197d:	mov    (%rdx,%rax,8),%rdx
  411981:	and    0x10(%rbx),%rdx
  411985:	movzwl (%rbx),%esi
  411988:	mov    %rbp,%rdi
  41198b:	mov    $0x0,%eax
  411990:	callq  4105df <TIFFSetField>
  411995:	mov    %eax,%r13d
  411998:	jmpq   41165b <TIFFFetchNormalTag+0xf5>
  41199d:	movzwl %ax,%eax
  4119a0:	mov    0x1e8(%rbp),%rdx
  4119a7:	mov    (%rdx,%rax,4),%ecx
  4119aa:	mov    0x10(%rbx),%rdx
  4119ae:	shr    %cl,%rdx
  4119b1:	mov    0x1f0(%rbp),%rcx
  4119b8:	and    (%rcx,%rax,8),%rdx
  4119bc:	jmp    411985 <TIFFFetchNormalTag+0x41f>
  4119be:	lea    0x20(%rsp),%rdx
  4119c3:	mov    %rbx,%rsi
  4119c6:	mov    %rbp,%rdi
  4119c9:	callq  410f55 <TIFFFetchData>
  4119ce:	movss  0x7426(%rip),%xmm0        # 418dfc <__dso_handle+0x34>
  4119d6:	test   %eax,%eax
  4119d8:	jne    4119f6 <TIFFFetchNormalTag+0x490>
  4119da:	cvtss2sd %xmm0,%xmm0
  4119de:	movzwl (%rbx),%esi
  4119e1:	mov    %rbp,%rdi
  4119e4:	mov    $0x1,%eax
  4119e9:	callq  4105df <TIFFSetField>
  4119ee:	mov    %eax,%r13d
  4119f1:	jmpq   41165b <TIFFFetchNormalTag+0xf5>
  4119f6:	lea    0x1c(%rsp),%r8
  4119fb:	mov    0x28(%rsp),%rcx
  411a00:	mov    0x20(%rsp),%rdx
  411a05:	mov    %rbx,%rsi
  411a08:	mov    %rbp,%rdi
  411a0b:	mov    $0x0,%eax
  411a10:	callq  411137 <cvtRational>
  411a15:	movss  0x73df(%rip),%xmm0        # 418dfc <__dso_handle+0x34>
  411a1d:	test   %eax,%eax
  411a1f:	je     4119da <TIFFFetchNormalTag+0x474>
  411a21:	movss  0x1c(%rsp),%xmm0
  411a27:	jmp    4119da <TIFFFetchNormalTag+0x474>
  411a29:	cmpw   $0x4d4d,0x1d8(%rbp)
  411a32:	je     411a6d <TIFFFetchNormalTag+0x507>
  411a34:	mov    0x1f0(%rbp),%rax
  411a3b:	mov    0x58(%rax),%rax
  411a3f:	and    0x10(%rbx),%rax
  411a43:	mov    %rax,%rdx
  411a46:	js     411ab1 <TIFFFetchNormalTag+0x54b>
  411a48:	pxor   %xmm0,%xmm0
  411a4c:	cvtsi2ss %rax,%xmm0
  411a51:	cvtss2sd %xmm0,%xmm0
  411a55:	movzwl (%rbx),%esi
  411a58:	mov    %rbp,%rdi
  411a5b:	mov    $0x1,%eax
  411a60:	callq  4105df <TIFFSetField>
  411a65:	mov    %eax,%r13d
  411a68:	jmpq   41165b <TIFFFetchNormalTag+0xf5>
  411a6d:	mov    0x1e8(%rbp),%rax
  411a74:	mov    0x2c(%rax),%ecx
  411a77:	mov    0x10(%rbx),%rax
  411a7b:	shr    %cl,%rax
  411a7e:	mov    0x1f0(%rbp),%rdx
  411a85:	and    0x58(%rdx),%rax
  411a89:	mov    %rax,%rdx
  411a8c:	js     411a99 <TIFFFetchNormalTag+0x533>
  411a8e:	pxor   %xmm0,%xmm0
  411a92:	cvtsi2ss %rax,%xmm0
  411a97:	jmp    411a51 <TIFFFetchNormalTag+0x4eb>
  411a99:	shr    %rax
  411a9c:	and    $0x1,%edx
  411a9f:	or     %rdx,%rax
  411aa2:	pxor   %xmm0,%xmm0
  411aa6:	cvtsi2ss %rax,%xmm0
  411aab:	addss  %xmm0,%xmm0
  411aaf:	jmp    411a51 <TIFFFetchNormalTag+0x4eb>
  411ab1:	shr    %rax
  411ab4:	and    $0x1,%edx
  411ab7:	or     %rdx,%rax
  411aba:	pxor   %xmm0,%xmm0
  411abe:	cvtsi2ss %rax,%xmm0
  411ac3:	addss  %xmm0,%xmm0
  411ac7:	jmp    411a51 <TIFFFetchNormalTag+0x4eb>
  411ac9:	lea    0x20(%rsp),%rdx
  411ace:	mov    %rbx,%rsi
  411ad1:	mov    %rbp,%rdi
  411ad4:	callq  4110e0 <TIFFFetchString>
  411ad9:	mov    %eax,%r13d
  411adc:	test   %eax,%eax
  411ade:	je     41165b <TIFFFetchNormalTag+0xf5>
  411ae4:	movb   $0x0,0x21(%rsp)
  411ae9:	movzwl (%rbx),%esi
  411aec:	lea    0x20(%rsp),%rdx
  411af1:	mov    %rbp,%rdi
  411af4:	mov    $0x0,%eax
  411af9:	callq  4105df <TIFFSetField>
  411afe:	mov    %eax,%r13d
  411b01:	jmpq   41165b <TIFFFetchNormalTag+0xf5>
  411b06:	mov    $0x0,%r13d
  411b0c:	jmpq   41165b <TIFFFetchNormalTag+0xf5>
  411b11:	mov    $0x0,%r13d
  411b17:	jmpq   41165b <TIFFFetchNormalTag+0xf5>

0000000000411b1c <TIFFReadDirectory>:
  411b1c:	mov    0x18(%rdi),%rsi
  411b20:	mov    %rsi,0x10(%rdi)
  411b24:	mov    $0x0,%eax
  411b29:	test   %rsi,%rsi
  411b2c:	je     412a24 <TIFFReadDirectory+0xf08>
  411b32:	push   %r15
  411b34:	push   %r14
  411b36:	push   %r13
  411b38:	push   %r12
  411b3a:	push   %rbp
  411b3b:	push   %rbx
  411b3c:	sub    $0x68,%rsp
  411b40:	mov    %rdi,%rbp
  411b43:	addl   $0x1,0x200(%rdi)
  411b4a:	testb  $0x1,0xf(%rdi)
  411b4e:	je     411c00 <TIFFReadDirectory+0xe4>
  411b54:	lea    0x2(%rsi),%rbx
  411b58:	cmp    0x2c0(%rdi),%rbx
  411b5f:	ja     411d26 <TIFFReadDirectory+0x20a>
  411b65:	add    0x2b8(%rdi),%rsi
  411b6c:	mov    %rsi,%rdi
  411b6f:	mov    $0x2,%edx
  411b74:	lea    0x5e(%rsp),%rsi
  411b79:	mov    $0x0,%eax
  411b7e:	callq  4012d0 <bcopy@plt>
  411b83:	testb  $0x10,0xe(%rbp)
  411b87:	jne    411d4c <TIFFReadDirectory+0x230>
  411b8d:	movzwl 0x5e(%rsp),%eax
  411b92:	lea    (%rax,%rax,2),%rsi
  411b96:	shl    $0x3,%rsi
  411b9a:	mov    $0x41a43e,%edx
  411b9f:	mov    %rbp,%rdi
  411ba2:	mov    $0x0,%eax
  411ba7:	callq  4111ff <CheckMalloc>
  411bac:	mov    %rax,%r14
  411baf:	mov    $0x0,%eax
  411bb4:	test   %r14,%r14
  411bb7:	je     411d3d <TIFFReadDirectory+0x221>
  411bbd:	movzwl 0x5e(%rsp),%eax
  411bc2:	lea    (%rax,%rax,2),%rdx
  411bc6:	shl    $0x3,%rdx
  411bca:	lea    (%rbx,%rdx,1),%rax
  411bce:	cmp    0x2c0(%rbp),%rax
  411bd5:	jbe    411d5b <TIFFReadDirectory+0x23f>
  411bdb:	mov    $0x41a455,%esi
  411be0:	mov    0x0(%rbp),%rdi
  411be4:	mov    $0x0,%eax
  411be9:	callq  412a93 <TIFFError>
  411bee:	mov    %r14,%rdi
  411bf1:	callq  4010b0 <free@plt>
  411bf6:	mov    $0x0,%eax
  411bfb:	jmpq   411d3d <TIFFReadDirectory+0x221>
  411c00:	movswl 0x8(%rdi),%edi
  411c04:	mov    $0x0,%edx
  411c09:	callq  401190 <lseek@plt>
  411c0e:	cmp    0x10(%rbp),%rax
  411c12:	je     411c31 <TIFFReadDirectory+0x115>
  411c14:	mov    $0x41a078,%esi
  411c19:	mov    0x0(%rbp),%rdi
  411c1d:	mov    $0x0,%eax
  411c22:	callq  412a93 <TIFFError>
  411c27:	mov    $0x0,%eax
  411c2c:	jmpq   411d3d <TIFFReadDirectory+0x221>
  411c31:	movswl 0x8(%rbp),%edi
  411c35:	mov    $0x2,%edx
  411c3a:	lea    0x5e(%rsp),%rsi
  411c3f:	mov    $0x0,%eax
  411c44:	callq  401200 <read@plt>
  411c49:	cmp    $0x2,%eax
  411c4c:	jne    411cd7 <TIFFReadDirectory+0x1bb>
  411c52:	testb  $0x10,0xe(%rbp)
  411c56:	jne    411cf1 <TIFFReadDirectory+0x1d5>
  411c5c:	movzwl 0x5e(%rsp),%eax
  411c61:	lea    (%rax,%rax,2),%rsi
  411c65:	shl    $0x3,%rsi
  411c69:	mov    $0x41a43e,%edx
  411c6e:	mov    %rbp,%rdi
  411c71:	mov    $0x0,%eax
  411c76:	callq  4111ff <CheckMalloc>
  411c7b:	mov    %rax,%r14
  411c7e:	mov    $0x0,%eax
  411c83:	test   %r14,%r14
  411c86:	je     411d3d <TIFFReadDirectory+0x221>
  411c8c:	movzwl 0x5e(%rsp),%eax
  411c91:	lea    (%rax,%rax,2),%rdx
  411c95:	shl    $0x3,%rdx
  411c99:	movswl 0x8(%rbp),%edi
  411c9d:	mov    %r14,%rsi
  411ca0:	mov    $0x0,%eax
  411ca5:	callq  401200 <read@plt>
  411caa:	movslq %eax,%rdx
  411cad:	movzwl 0x5e(%rsp),%eax
  411cb2:	lea    (%rax,%rax,2),%rax
  411cb6:	shl    $0x3,%rax
  411cba:	cmp    %rax,%rdx
  411cbd:	je     411d00 <TIFFReadDirectory+0x1e4>
  411cbf:	mov    $0x41a455,%esi
  411cc4:	mov    0x0(%rbp),%rdi
  411cc8:	mov    $0x0,%eax
  411ccd:	callq  412a93 <TIFFError>
  411cd2:	jmpq   411bee <TIFFReadDirectory+0xd2>
  411cd7:	mov    $0x41a0a0,%esi
  411cdc:	mov    0x0(%rbp),%rdi
  411ce0:	mov    $0x0,%eax
  411ce5:	callq  412a93 <TIFFError>
  411cea:	mov    $0x0,%eax
  411cef:	jmp    411d3d <TIFFReadDirectory+0x221>
  411cf1:	lea    0x5e(%rsp),%rdi
  411cf6:	callq  413028 <TIFFSwabShort>
  411cfb:	jmpq   411c5c <TIFFReadDirectory+0x140>
  411d00:	lea    0x18(%rbp),%rsi
  411d04:	movswl 0x8(%rbp),%edi
  411d08:	mov    $0x8,%edx
  411d0d:	mov    $0x0,%eax
  411d12:	callq  401200 <read@plt>
  411d17:	cmp    $0x8,%eax
  411d1a:	je     411d94 <TIFFReadDirectory+0x278>
  411d1c:	movq   $0x0,0x18(%rbp)
  411d24:	jmp    411d94 <TIFFReadDirectory+0x278>
  411d26:	mov    $0x41a0a0,%esi
  411d2b:	mov    (%rdi),%rdi
  411d2e:	mov    $0x0,%eax
  411d33:	callq  412a93 <TIFFError>
  411d38:	mov    $0x0,%eax
  411d3d:	add    $0x68,%rsp
  411d41:	pop    %rbx
  411d42:	pop    %rbp
  411d43:	pop    %r12
  411d45:	pop    %r13
  411d47:	pop    %r14
  411d49:	pop    %r15
  411d4b:	retq   
  411d4c:	lea    0x5e(%rsp),%rdi
  411d51:	callq  413028 <TIFFSwabShort>
  411d56:	jmpq   411b8d <TIFFReadDirectory+0x71>
  411d5b:	mov    %rbx,%rdi
  411d5e:	add    0x2b8(%rbp),%rdi
  411d65:	mov    %r14,%rsi
  411d68:	mov    $0x0,%eax
  411d6d:	callq  4012d0 <bcopy@plt>
  411d72:	movzwl 0x5e(%rsp),%eax
  411d77:	lea    (%rax,%rax,2),%rax
  411d7b:	lea    (%rbx,%rax,8),%rax
  411d7f:	lea    0x8(%rax),%rdx
  411d83:	cmp    0x2c0(%rbp),%rdx
  411d8a:	jb     411df6 <TIFFReadDirectory+0x2da>
  411d8c:	movq   $0x0,0x18(%rbp)
  411d94:	testb  $0x10,0xe(%rbp)
  411d98:	jne    411e18 <TIFFReadDirectory+0x2fc>
  411d9a:	andw   $0xfff7,0xe(%rbp)
  411d9f:	mov    %rbp,%rdi
  411da2:	callq  410961 <TIFFFreeDirectory>
  411da7:	mov    %rbp,%rdi
  411daa:	callq  410c5b <TIFFDefaultDirectory>
  411daf:	mov    $0x1,%edx
  411db4:	mov    $0x11c,%esi
  411db9:	mov    %rbp,%rdi
  411dbc:	mov    $0x0,%eax
  411dc1:	callq  4105df <TIFFSetField>
  411dc6:	movzwl 0x5e(%rsp),%eax
  411dcb:	test   %ax,%ax
  411dce:	je     411ff2 <TIFFReadDirectory+0x4d6>
  411dd4:	movzwl %ax,%eax
  411dd7:	lea    -0x1(%rax),%eax
  411dda:	lea    0x3(%rax,%rax,2),%rax
  411ddf:	lea    (%r14,%rax,8),%r13
  411de3:	mov    %r14,%r12
  411de6:	mov    $0x0,%r15d
  411dec:	mov    $0x61f220,%ebx
  411df1:	jmpq   411e92 <TIFFReadDirectory+0x376>
  411df6:	lea    0x18(%rbp),%rsi
  411dfa:	add    0x2b8(%rbp),%rax
  411e01:	mov    %rax,%rdi
  411e04:	mov    $0x8,%edx
  411e09:	mov    $0x0,%eax
  411e0e:	callq  4012d0 <bcopy@plt>
  411e13:	jmpq   411d94 <TIFFReadDirectory+0x278>
  411e18:	lea    0x18(%rbp),%rdi
  411e1c:	callq  413035 <TIFFSwabLong>
  411e21:	jmpq   411d9a <TIFFReadDirectory+0x27e>
  411e26:	mov    $0x2,%esi
  411e2b:	mov    %r12,%rdi
  411e2e:	callq  413050 <TIFFSwabArrayOfShort>
  411e33:	lea    0x8(%r12),%rdi
  411e38:	mov    $0x2,%esi
  411e3d:	callq  413073 <TIFFSwabArrayOfLong>
  411e42:	jmp    411e98 <TIFFReadDirectory+0x37c>
  411e44:	mov    $0x41a0c8,%esi
  411e49:	mov    0x0(%rbp),%rdi
  411e4d:	mov    $0x0,%eax
  411e52:	callq  413526 <TIFFWarning>
  411e57:	mov    $0x1,%r15d
  411e5d:	jmp    411eac <TIFFReadDirectory+0x390>
  411e5f:	movzwl (%r12),%edx
  411e64:	mov    %edx,%ecx
  411e66:	mov    $0x41a108,%esi
  411e6b:	mov    0x0(%rbp),%rdi
  411e6f:	mov    $0x0,%eax
  411e74:	callq  413526 <TIFFWarning>
  411e79:	movw   $0x0,(%r12)
  411e80:	mov    $0x61f220,%ebx
  411e85:	add    $0x18,%r12
  411e89:	cmp    %r12,%r13
  411e8c:	je     411ff2 <TIFFReadDirectory+0x4d6>
  411e92:	testb  $0x10,0xe(%rbp)
  411e96:	jne    411e26 <TIFFReadDirectory+0x30a>
  411e98:	movzwl (%rbx),%eax
  411e9b:	cmp    %ax,(%r12)
  411ea0:	jae    411eac <TIFFReadDirectory+0x390>
  411ea2:	mov    $0x61f220,%ebx
  411ea7:	test   %r15d,%r15d
  411eaa:	je     411e44 <TIFFReadDirectory+0x328>
  411eac:	movzwl (%rbx),%eax
  411eaf:	test   %ax,%ax
  411eb2:	je     411e5f <TIFFReadDirectory+0x343>
  411eb4:	movzwl (%r12),%ecx
  411eb9:	cmp    %cx,%ax
  411ebc:	jae    411ecf <TIFFReadDirectory+0x3b3>
  411ebe:	add    $0x18,%rbx
  411ec2:	movzwl (%rbx),%eax
  411ec5:	test   %ax,%ax
  411ec8:	je     411e5f <TIFFReadDirectory+0x343>
  411eca:	cmp    %cx,%ax
  411ecd:	jb     411ebe <TIFFReadDirectory+0x3a2>
  411ecf:	cmp    %cx,%ax
  411ed2:	jne    411e5f <TIFFReadDirectory+0x343>
  411ed4:	cmpw   $0xffff,0xc(%rbx)
  411ed9:	je     411f18 <TIFFReadDirectory+0x3fc>
  411edb:	movzwl 0x2(%r12),%edx
  411ee1:	mov    0x8(%rbx),%eax
  411ee4:	test   %eax,%eax
  411ee6:	je     411f24 <TIFFReadDirectory+0x408>
  411ee8:	cmp    %ax,%dx
  411eeb:	je     411f24 <TIFFReadDirectory+0x408>
  411eed:	add    $0x18,%rbx
  411ef1:	movzwl (%rbx),%eax
  411ef4:	cmp    %cx,%ax
  411ef7:	jne    411efe <TIFFReadDirectory+0x3e2>
  411ef9:	test   %ax,%ax
  411efc:	jne    411ee1 <TIFFReadDirectory+0x3c5>
  411efe:	mov    -0x8(%rbx),%rcx
  411f02:	movzwl %dx,%edx
  411f05:	mov    $0x41a138,%esi
  411f0a:	mov    0x0(%rbp),%rdi
  411f0e:	mov    $0x0,%eax
  411f13:	callq  413526 <TIFFWarning>
  411f18:	movw   $0x0,(%r12)
  411f1f:	jmpq   411e85 <TIFFReadDirectory+0x369>
  411f24:	movzwl 0x2(%rbx),%eax
  411f28:	cmp    $0xffff,%ax
  411f2c:	je     411f47 <TIFFReadDirectory+0x42b>
  411f2e:	movswq %ax,%rdx
  411f32:	cmp    $0xfffe,%ax
  411f36:	je     411f9e <TIFFReadDirectory+0x482>
  411f38:	mov    %r12,%rsi
  411f3b:	mov    %rbp,%rdi
  411f3e:	callq  410f0e <CheckDirCount>
  411f43:	test   %eax,%eax
  411f45:	je     411f18 <TIFFReadDirectory+0x3fc>
  411f47:	movzwl (%r12),%eax
  411f4c:	cmp    $0x11c,%ax
  411f50:	je     411fb2 <TIFFReadDirectory+0x496>
  411f52:	cmp    $0x11c,%ax
  411f56:	ja     411fca <TIFFReadDirectory+0x4ae>
  411f58:	cmp    $0x111,%ax
  411f5c:	je     411f7e <TIFFReadDirectory+0x462>
  411f5e:	cmp    $0x111,%ax
  411f62:	jbe    411fa4 <TIFFReadDirectory+0x488>
  411f64:	cmp    $0x115,%ax
  411f68:	jb     411e85 <TIFFReadDirectory+0x369>
  411f6e:	cmp    $0x116,%ax
  411f72:	jbe    411fb2 <TIFFReadDirectory+0x496>
  411f74:	cmp    $0x117,%ax
  411f78:	jne    411e85 <TIFFReadDirectory+0x369>
  411f7e:	movzwl 0xc(%rbx),%ecx
  411f82:	mov    %ecx,%eax
  411f84:	shr    $0x5,%ax
  411f88:	movzwl %ax,%eax
  411f8b:	mov    $0x1,%edx
  411f90:	shl    %cl,%edx
  411f92:	mov    %edx,%edx
  411f94:	or     %rdx,0x20(%rbp,%rax,8)
  411f99:	jmpq   411e85 <TIFFReadDirectory+0x369>
  411f9e:	movzwl 0x70(%rbp),%edx
  411fa2:	jmp    411f38 <TIFFReadDirectory+0x41c>
  411fa4:	sub    $0x100,%ax
  411fa8:	cmp    $0x1,%ax
  411fac:	ja     411e85 <TIFFReadDirectory+0x369>
  411fb2:	mov    %r12,%rsi
  411fb5:	mov    %rbp,%rdi
  411fb8:	callq  411566 <TIFFFetchNormalTag>
  411fbd:	test   %eax,%eax
  411fbf:	jne    411e85 <TIFFReadDirectory+0x369>
  411fc5:	jmpq   41227d <TIFFReadDirectory+0x761>
  411fca:	cmp    $0x145,%ax
  411fce:	ja     411fe2 <TIFFReadDirectory+0x4c6>
  411fd0:	cmp    $0x144,%ax
  411fd4:	jae    411f7e <TIFFReadDirectory+0x462>
  411fd6:	cmp    $0x142,%ax
  411fda:	jb     411e85 <TIFFReadDirectory+0x369>
  411fe0:	jmp    411fb2 <TIFFReadDirectory+0x496>
  411fe2:	add    $0x7f1b,%ax
  411fe6:	cmp    $0x1,%ax
  411fea:	ja     411e85 <TIFFReadDirectory+0x369>
  411ff0:	jmp    411fb2 <TIFFReadDirectory+0x496>
  411ff2:	mov    0x20(%rbp),%rax
  411ff6:	test   $0x1,%al
  411ff8:	je     4120ac <TIFFReadDirectory+0x590>
  411ffe:	test   $0x100000,%eax
  412003:	je     4120be <TIFFReadDirectory+0x5a2>
  412009:	test   $0x2,%al
  41200b:	jne    4120e0 <TIFFReadDirectory+0x5c4>
  412011:	mov    0x78(%rbp),%rcx
  412015:	mov    $0xffffffff,%eax
  41201a:	cmp    %rax,%rcx
  41201d:	je     4120d0 <TIFFReadDirectory+0x5b4>
  412023:	mov    %ecx,%eax
  412025:	add    0x38(%rbp),%eax
  412028:	sub    $0x1,%eax
  41202b:	mov    $0x0,%edx
  412030:	div    %ecx
  412032:	mov    %eax,%eax
  412034:	mov    %rax,0x138(%rbp)
  41203b:	mov    0x30(%rbp),%rax
  41203f:	mov    %rax,0x48(%rbp)
  412043:	mov    %rcx,0x50(%rbp)
  412047:	mov    0x40(%rbp),%rax
  41204b:	mov    %rax,0x58(%rbp)
  41204f:	andw   $0xff7f,0xe(%rbp)
  412055:	mov    0x138(%rbp),%rax
  41205c:	mov    %rax,0x140(%rbp)
  412063:	cmpw   $0x2,0x9a(%rbp)
  41206b:	je     4120fc <TIFFReadDirectory+0x5e0>
  412071:	cmpq   $0x0,0x140(%rbp)
  412079:	je     412110 <TIFFReadDirectory+0x5f4>
  41207f:	testb  $0x8,0x23(%rbp)
  412083:	jne    412110 <TIFFReadDirectory+0x5f4>
  412089:	movzwl 0xe(%rbp),%eax
  41208d:	and    $0x80,%ax
  412091:	mov    $0x419e43,%esi
  412096:	mov    $0x419c82,%eax
  41209b:	cmove  %rax,%rsi
  41209f:	mov    %rbp,%rdi
  4120a2:	callq  410ef0 <MissingRequired>
  4120a7:	jmpq   41227d <TIFFReadDirectory+0x761>
  4120ac:	mov    $0x419bec,%esi
  4120b1:	mov    %rbp,%rdi
  4120b4:	callq  410ef0 <MissingRequired>
  4120b9:	jmpq   41227d <TIFFReadDirectory+0x761>
  4120be:	mov    $0x419cfe,%esi
  4120c3:	mov    %rbp,%rdi
  4120c6:	callq  410ef0 <MissingRequired>
  4120cb:	jmpq   41227d <TIFFReadDirectory+0x761>
  4120d0:	cmpq   $0x0,0x38(%rbp)
  4120d5:	setne  %al
  4120d8:	movzbl %al,%eax
  4120db:	jmpq   412034 <TIFFReadDirectory+0x518>
  4120e0:	mov    %rbp,%rdi
  4120e3:	callq  413326 <TIFFNumberOfTiles>
  4120e8:	mov    %eax,%eax
  4120ea:	mov    %rax,0x138(%rbp)
  4120f1:	orw    $0x80,0xe(%rbp)
  4120f7:	jmpq   412055 <TIFFReadDirectory+0x539>
  4120fc:	movzwl 0x70(%rbp),%edx
  412100:	imul   %rdx,%rax
  412104:	mov    %rax,0x140(%rbp)
  41210b:	jmpq   412071 <TIFFReadDirectory+0x555>
  412110:	movzwl 0x5e(%rsp),%eax
  412115:	test   %ax,%ax
  412118:	je     4128ba <TIFFReadDirectory+0xd9e>
  41211e:	movzwl %ax,%eax
  412121:	lea    -0x1(%rax),%eax
  412124:	lea    0x3(%rax,%rax,2),%rax
  412129:	lea    (%r14,%rax,8),%r12
  41212d:	mov    %r14,%rbx
  412130:	lea    0xe8(%rbp),%rax
  412137:	mov    %rax,(%rsp)
  41213b:	lea    0x150(%rbp),%rax
  412142:	mov    %rax,0x8(%rsp)
  412147:	jmpq   4124e7 <TIFFReadDirectory+0x9cb>
  41214c:	cmp    $0x116,%ax
  412150:	jbe    412194 <TIFFReadDirectory+0x678>
  412152:	cmp    $0x11c,%ax
  412156:	je     4124da <TIFFReadDirectory+0x9be>
  41215c:	cmp    $0x11c,%ax
  412160:	jbe    412242 <TIFFReadDirectory+0x726>
  412166:	cmp    $0x12d,%ax
  41216a:	je     412615 <TIFFReadDirectory+0xaf9>
  412170:	cmp    $0x140,%ax
  412174:	je     4125f6 <TIFFReadDirectory+0xada>
  41217a:	cmp    $0x129,%ax
  41217e:	je     4126a9 <TIFFReadDirectory+0xb8d>
  412184:	mov    %rbx,%rsi
  412187:	mov    %rbp,%rdi
  41218a:	callq  411566 <TIFFFetchNormalTag>
  41218f:	jmpq   4124da <TIFFReadDirectory+0x9be>
  412194:	cmp    $0x115,%ax
  412198:	jae    4124da <TIFFReadDirectory+0x9be>
  41219e:	cmp    $0x103,%ax
  4121a2:	ja     412215 <TIFFReadDirectory+0x6f9>
  4121a4:	cmp    $0x102,%ax
  4121a8:	jae    412256 <TIFFReadDirectory+0x73a>
  4121ae:	cmp    $0xff,%ax
  4121b2:	jne    412206 <TIFFReadDirectory+0x6ea>
  4121b4:	cmpw   $0x4d4d,0x1d8(%rbp)
  4121bd:	je     412895 <TIFFReadDirectory+0xd79>
  4121c3:	movzwl 0x2(%rbx),%edx
  4121c7:	mov    0x1f0(%rbp),%rax
  4121ce:	mov    (%rax,%rdx,8),%rax
  4121d2:	and    0x10(%rbx),%rax
  4121d6:	cmp    $0x2,%rax
  4121da:	je     412a1a <TIFFReadDirectory+0xefe>
  4121e0:	mov    $0x2,%edx
  4121e5:	cmp    $0x3,%rax
  4121e9:	jne    4124da <TIFFReadDirectory+0x9be>
  4121ef:	mov    $0xfe,%esi
  4121f4:	mov    %rbp,%rdi
  4121f7:	mov    $0x0,%eax
  4121fc:	callq  4105df <TIFFSetField>
  412201:	jmpq   4124da <TIFFReadDirectory+0x9be>
  412206:	cmp    $0x101,%ax
  41220a:	je     4124da <TIFFReadDirectory+0x9be>
  412210:	jmpq   412184 <TIFFReadDirectory+0x668>
  412215:	cmp    $0x111,%ax
  412219:	jne    412184 <TIFFReadDirectory+0x668>
  41221f:	lea    0x148(%rbp),%rcx
  412226:	mov    0x140(%rbp),%rdx
  41222d:	mov    %rbx,%rsi
  412230:	mov    %rbp,%rdi
  412233:	callq  41123d <TIFFFetchStripThing>
  412238:	test   %eax,%eax
  41223a:	jne    4124da <TIFFReadDirectory+0x9be>
  412240:	jmp    41227d <TIFFReadDirectory+0x761>
  412242:	cmp    $0x117,%ax
  412246:	je     412307 <TIFFReadDirectory+0x7eb>
  41224c:	cmp    $0x119,%ax
  412250:	ja     412184 <TIFFReadDirectory+0x668>
  412256:	cmpq   $0x1,0x8(%rbx)
  41225b:	je     4123f1 <TIFFReadDirectory+0x8d5>
  412261:	movzwl 0x70(%rbp),%r13d
  412266:	movzwl %r13w,%edx
  41226a:	mov    %rbx,%rsi
  41226d:	mov    %rbp,%rdi
  412270:	callq  410f0e <CheckDirCount>
  412275:	test   %eax,%eax
  412277:	jne    41244e <TIFFReadDirectory+0x932>
  41227d:	mov    $0x0,%eax
  412282:	test   %r14,%r14
  412285:	je     411d3d <TIFFReadDirectory+0x221>
  41228b:	jmpq   411bee <TIFFReadDirectory+0xd2>
  412290:	cmp    $0x144,%ax
  412294:	je     41221f <TIFFReadDirectory+0x703>
  412296:	cmp    $0x144,%ax
  41229a:	jb     4124da <TIFFReadDirectory+0x9be>
  4122a0:	cmp    $0x150,%ax
  4122a4:	je     4127ab <TIFFReadDirectory+0xc8f>
  4122aa:	cmp    $0x152,%ax
  4122ae:	jne    4122fd <TIFFReadDirectory+0x7e1>
  4122b0:	cmpq   $0x1,0x8(%rbx)
  4122b5:	jne    41283d <TIFFReadDirectory+0xd21>
  4122bb:	cmpw   $0x4d4d,0x1d8(%rbp)
  4122c4:	je     412855 <TIFFReadDirectory+0xd39>
  4122ca:	movzwl 0x2(%rbx),%ecx
  4122ce:	mov    0x1f0(%rbp),%rdx
  4122d5:	mov    0x10(%rbx),%rax
  4122d9:	and    (%rdx,%rcx,8),%eax
  4122dc:	cmp    $0x1,%eax
  4122df:	je     412879 <TIFFReadDirectory+0xd5d>
  4122e5:	mov    $0x41a1f8,%esi
  4122ea:	mov    0x0(%rbp),%rdi
  4122ee:	mov    $0x0,%eax
  4122f3:	callq  412a93 <TIFFError>
  4122f8:	jmpq   4124da <TIFFReadDirectory+0x9be>
  4122fd:	cmp    $0x145,%ax
  412301:	jne    412184 <TIFFReadDirectory+0x668>
  412307:	mov    0x140(%rbp),%rdx
  41230e:	mov    0x8(%rsp),%rcx
  412313:	mov    %rbx,%rsi
  412316:	mov    %rbp,%rdi
  412319:	callq  41123d <TIFFFetchStripThing>
  41231e:	test   %eax,%eax
  412320:	jne    4124da <TIFFReadDirectory+0x9be>
  412326:	jmpq   41227d <TIFFReadDirectory+0x761>
  41232b:	cmp    $0x80e4,%ax
  41232f:	je     412261 <TIFFReadDirectory+0x745>
  412335:	cmp    $0x80e6,%ax
  412339:	je     4124da <TIFFReadDirectory+0x9be>
  41233f:	cmp    $0x214,%ax
  412343:	jne    412184 <TIFFReadDirectory+0x668>
  412349:	movzwl 0x70(%rbp),%edx
  41234d:	add    %edx,%edx
  41234f:	movslq %edx,%rdx
  412352:	mov    %rbx,%rsi
  412355:	mov    %rbp,%rdi
  412358:	callq  410f0e <CheckDirCount>
  41235d:	test   %eax,%eax
  41235f:	je     4124da <TIFFReadDirectory+0x9be>
  412365:	cmpw   $0x5,0x2(%rbx)
  41236a:	je     4126f4 <TIFFReadDirectory+0xbd8>
  412370:	mov    0x8(%rbx),%rax
  412374:	lea    0x0(,%rax,8),%rsi
  41237c:	mov    $0x61fae0,%edx
  412381:	mov    %rbp,%rdi
  412384:	mov    $0x0,%eax
  412389:	callq  4111ff <CheckMalloc>
  41238e:	mov    %rax,%r13
  412391:	test   %rax,%rax
  412394:	je     4124da <TIFFReadDirectory+0x9be>
  41239a:	cmpq   $0x1,0x8(%rbx)
  41239f:	jne    412704 <TIFFReadDirectory+0xbe8>
  4123a5:	mov    0x10(%rbx),%rax
  4123a9:	mov    %rax,0x0(%r13)
  4123ad:	mov    0x8(%rbx),%rax
  4123b1:	lea    0x0(,%rax,4),%rsi
  4123b9:	mov    $0x61fae0,%edx
  4123be:	mov    %rbp,%rdi
  4123c1:	mov    $0x0,%eax
  4123c6:	callq  4111ff <CheckMalloc>
  4123cb:	mov    %rax,%r15
  4123ce:	test   %rax,%rax
  4123d1:	je     41271a <TIFFReadDirectory+0xbfe>
  4123d7:	cmpq   $0x0,0x8(%rbx)
  4123dc:	je     412767 <TIFFReadDirectory+0xc4b>
  4123e2:	mov    $0x0,%esi
  4123e7:	mov    $0x0,%ecx
  4123ec:	jmpq   412752 <TIFFReadDirectory+0xc36>
  4123f1:	cmpw   $0x4d4d,0x1d8(%rbp)
  4123fa:	je     41242c <TIFFReadDirectory+0x910>
  4123fc:	movzwl 0x2(%rbx),%ecx
  412400:	mov    0x1f0(%rbp),%rdx
  412407:	mov    (%rdx,%rcx,8),%rdx
  41240b:	and    0x10(%rbx),%rdx
  41240f:	movzwl %ax,%esi
  412412:	mov    %rbp,%rdi
  412415:	mov    $0x0,%eax
  41241a:	callq  4105df <TIFFSetField>
  41241f:	test   %eax,%eax
  412421:	jne    4124da <TIFFReadDirectory+0x9be>
  412427:	jmpq   41227d <TIFFReadDirectory+0x761>
  41242c:	movzwl 0x2(%rbx),%esi
  412430:	mov    0x1e8(%rbp),%rdx
  412437:	mov    (%rdx,%rsi,4),%ecx
  41243a:	mov    0x10(%rbx),%rdx
  41243e:	shr    %cl,%rdx
  412441:	mov    0x1f0(%rbp),%rcx
  412448:	and    (%rcx,%rsi,8),%rdx
  41244c:	jmp    41240f <TIFFReadDirectory+0x8f3>
  41244e:	lea    0x30(%rsp),%rdx
  412453:	mov    %rbx,%rsi
  412456:	mov    %rbp,%rdi
  412459:	callq  411067 <TIFFFetchShortArray>
  41245e:	test   %eax,%eax
  412460:	je     41227d <TIFFReadDirectory+0x761>
  412466:	cmp    $0x1,%r13w
  41246b:	jbe    4124bd <TIFFReadDirectory+0x9a1>
  41246d:	movzwl 0x32(%rsp),%ecx
  412472:	cmp    0x30(%rsp),%cx
  412477:	jne    412499 <TIFFReadDirectory+0x97d>
  412479:	lea    0x34(%rsp),%rax
  41247e:	movzwl %r13w,%r13d
  412482:	lea    -0x2(%r13),%edx
  412486:	lea    (%rax,%rdx,2),%rdx
  41248a:	cmp    %rdx,%rax
  41248d:	je     4124bd <TIFFReadDirectory+0x9a1>
  41248f:	add    $0x2,%rax
  412493:	cmp    %cx,-0x2(%rax)
  412497:	je     41248a <TIFFReadDirectory+0x96e>
  412499:	movzwl (%rbx),%edi
  41249c:	callq  410ebe <TIFFFieldWithTag>
  4124a1:	mov    0x10(%rax),%rdx
  4124a5:	mov    $0x41a168,%esi
  4124aa:	mov    0x0(%rbp),%rdi
  4124ae:	mov    $0x0,%eax
  4124b3:	callq  412a93 <TIFFError>
  4124b8:	jmpq   41227d <TIFFReadDirectory+0x761>
  4124bd:	movzwl 0x30(%rsp),%edx
  4124c2:	movzwl (%rbx),%esi
  4124c5:	mov    %rbp,%rdi
  4124c8:	mov    $0x0,%eax
  4124cd:	callq  4105df <TIFFSetField>
  4124d2:	test   %eax,%eax
  4124d4:	je     41227d <TIFFReadDirectory+0x761>
  4124da:	add    $0x18,%rbx
  4124de:	cmp    %r12,%rbx
  4124e1:	je     4128ba <TIFFReadDirectory+0xd9e>
  4124e7:	movzwl (%rbx),%eax
  4124ea:	test   %ax,%ax
  4124ed:	je     4124da <TIFFReadDirectory+0x9be>
  4124ef:	cmp    $0x141,%ax
  4124f3:	je     4126d0 <TIFFReadDirectory+0xbb4>
  4124f9:	cmp    $0x141,%ax
  4124fd:	jbe    41214c <TIFFReadDirectory+0x630>
  412503:	cmp    $0x153,%ax
  412507:	je     412261 <TIFFReadDirectory+0x745>
  41250d:	cmp    $0x153,%ax
  412511:	jbe    412290 <TIFFReadDirectory+0x774>
  412517:	cmp    $0x212,%ax
  41251b:	je     412784 <TIFFReadDirectory+0xc68>
  412521:	cmp    $0x212,%ax
  412525:	ja     41232b <TIFFReadDirectory+0x80f>
  41252b:	cmp    $0x208,%ax
  41252f:	je     4127ef <TIFFReadDirectory+0xcd3>
  412535:	cmp    $0x209,%ax
  412539:	je     412816 <TIFFReadDirectory+0xcfa>
  41253f:	cmp    $0x207,%ax
  412543:	jne    412184 <TIFFReadDirectory+0x668>
  412549:	cmpq   $0x1,0x8(%rbx)
  41254e:	ja     4127d2 <TIFFReadDirectory+0xcb6>
  412554:	mov    0x10(%rbx),%rax
  412558:	mov    %rax,0x30(%rsp)
  41255d:	mov    0x8(%rbx),%rax
  412561:	lea    (%rax,%rax,8),%rsi
  412565:	shl    $0x3,%rsi
  412569:	mov    $0x41a471,%edx
  41256e:	mov    %rbp,%rdi
  412571:	mov    $0x0,%eax
  412576:	callq  4111ff <CheckMalloc>
  41257b:	mov    %rax,0x170(%rbp)
  412582:	test   %rax,%rax
  412585:	je     4124da <TIFFReadDirectory+0x9be>
  41258b:	movw   $0x1,0x12(%rsp)
  412592:	movq   $0x40,0x18(%rsp)
  41259b:	mov    0x8(%rbx),%rdx
  41259f:	lea    (%rax,%rdx,8),%r15
  4125a3:	test   %rdx,%rdx
  4125a6:	je     4125e9 <TIFFReadDirectory+0xacd>
  4125a8:	mov    $0x0,%r13d
  4125ae:	mov    0x170(%rbp),%rax
  4125b5:	mov    %r15,(%rax,%r13,8)
  4125b9:	mov    0x30(%rsp,%r13,8),%rax
  4125be:	mov    %rax,0x20(%rsp)
  4125c3:	mov    %r15,%rdx
  4125c6:	lea    0x10(%rsp),%rsi
  4125cb:	mov    %rbp,%rdi
  4125ce:	callq  410f55 <TIFFFetchData>
  4125d3:	test   %eax,%eax
  4125d5:	je     4124da <TIFFReadDirectory+0x9be>
  4125db:	add    $0x40,%r15
  4125df:	add    $0x1,%r13
  4125e3:	cmp    %r13,0x8(%rbx)
  4125e7:	ja     4125ae <TIFFReadDirectory+0xa92>
  4125e9:	orq    $0x20000,0x28(%rbp)
  4125f1:	jmpq   4124da <TIFFReadDirectory+0x9be>
  4125f6:	movzwl 0x62(%rbp),%ecx
  4125fa:	mov    $0x3,%edx
  4125ff:	shl    %cl,%rdx
  412602:	mov    %rbx,%rsi
  412605:	mov    %rbp,%rdi
  412608:	callq  410f0e <CheckDirCount>
  41260d:	test   %eax,%eax
  41260f:	je     4124da <TIFFReadDirectory+0x9be>
  412615:	movzwl 0x62(%rbp),%r15d
  41261a:	mov    0x8(%rbx),%rax
  41261e:	lea    (%rax,%rax,1),%rsi
  412622:	mov    $0x41a1a8,%edx
  412627:	mov    %rbp,%rdi
  41262a:	mov    $0x0,%eax
  41262f:	callq  4111ff <CheckMalloc>
  412634:	mov    %rax,%r13
  412637:	test   %rax,%rax
  41263a:	je     4124da <TIFFReadDirectory+0x9be>
  412640:	mov    %rax,%rdx
  412643:	mov    %rbx,%rsi
  412646:	mov    %rbp,%rdi
  412649:	callq  410f55 <TIFFFetchData>
  41264e:	test   %eax,%eax
  412650:	je     41269c <TIFFReadDirectory+0xb80>
  412652:	movzwl 0x62(%rbp),%ecx
  412656:	mov    $0x1,%eax
  41265b:	shl    %cl,%rax
  41265e:	mov    %rax,%rdx
  412661:	mov    $0x0,%eax
  412666:	cmp    %rdx,0x8(%rbx)
  41266a:	je     412677 <TIFFReadDirectory+0xb5b>
  41266c:	mov    $0x2,%eax
  412671:	mov    %r15d,%ecx
  412674:	shl    %cl,%rax
  412677:	lea    (%rax,%rax,2),%r8
  41267b:	add    %r13,%r8
  41267e:	lea    0x0(%r13,%rax,1),%rcx
  412683:	movzwl (%rbx),%esi
  412686:	mov    %r8,%r9
  412689:	sub    %rax,%r8
  41268c:	mov    %r13,%rdx
  41268f:	mov    %rbp,%rdi
  412692:	mov    $0x0,%eax
  412697:	callq  4105df <TIFFSetField>
  41269c:	mov    %r13,%rdi
  41269f:	callq  4010b0 <free@plt>
  4126a4:	jmpq   4124da <TIFFReadDirectory+0x9be>
  4126a9:	lea    0xb8(%rbp),%rdx
  4126b0:	mov    %rbx,%rsi
  4126b3:	mov    %rbp,%rdi
  4126b6:	callq  411067 <TIFFFetchShortArray>
  4126bb:	test   %eax,%eax
  4126bd:	je     4124da <TIFFReadDirectory+0x9be>
  4126c3:	orq    $0x2000000,0x20(%rbp)
  4126cb:	jmpq   4124da <TIFFReadDirectory+0x9be>
  4126d0:	mov    (%rsp),%rdx
  4126d4:	mov    %rbx,%rsi
  4126d7:	mov    %rbp,%rdi
  4126da:	callq  411067 <TIFFFetchShortArray>
  4126df:	test   %eax,%eax
  4126e1:	je     4124da <TIFFReadDirectory+0x9be>
  4126e7:	orq    $0x800,0x28(%rbp)
  4126ef:	jmpq   4124da <TIFFReadDirectory+0x9be>
  4126f4:	mov    %rbx,%rsi
  4126f7:	mov    %rbp,%rdi
  4126fa:	callq  411566 <TIFFFetchNormalTag>
  4126ff:	jmpq   4124da <TIFFReadDirectory+0x9be>
  412704:	mov    %rax,%rdx
  412707:	mov    %rbx,%rsi
  41270a:	mov    %rbp,%rdi
  41270d:	callq  410f55 <TIFFFetchData>
  412712:	test   %eax,%eax
  412714:	jne    4123ad <TIFFReadDirectory+0x891>
  41271a:	mov    %r13,%rdi
  41271d:	callq  4010b0 <free@plt>
  412722:	jmpq   4124da <TIFFReadDirectory+0x9be>
  412727:	mov    %rdx,%rax
  41272a:	shr    %rax
  41272d:	and    $0x1,%edx
  412730:	or     %rdx,%rax
  412733:	pxor   %xmm0,%xmm0
  412737:	cvtsi2ss %rax,%xmm0
  41273c:	addss  %xmm0,%xmm0
  412740:	movss  %xmm0,(%r15,%rcx,4)
  412746:	add    $0x1,%esi
  412749:	movslq %esi,%rcx
  41274c:	cmp    0x8(%rbx),%rcx
  412750:	jae    412767 <TIFFReadDirectory+0xc4b>
  412752:	mov    0x0(%r13,%rcx,8),%rdx
  412757:	test   %rdx,%rdx
  41275a:	js     412727 <TIFFReadDirectory+0xc0b>
  41275c:	pxor   %xmm0,%xmm0
  412760:	cvtsi2ss %rdx,%xmm0
  412765:	jmp    412740 <TIFFReadDirectory+0xc24>
  412767:	movzwl (%rbx),%esi
  41276a:	mov    %r15,%rdx
  41276d:	mov    %rbp,%rdi
  412770:	mov    $0x0,%eax
  412775:	callq  4105df <TIFFSetField>
  41277a:	mov    %r15,%rdi
  41277d:	callq  4010b0 <free@plt>
  412782:	jmp    41271a <TIFFReadDirectory+0xbfe>
  412784:	lea    0x160(%rbp),%rdx
  41278b:	mov    %rbx,%rsi
  41278e:	mov    %rbp,%rdi
  412791:	callq  411067 <TIFFFetchShortArray>
  412796:	test   %eax,%eax
  412798:	je     4124da <TIFFReadDirectory+0x9be>
  41279e:	orq    $0x2000,0x28(%rbp)
  4127a6:	jmpq   4124da <TIFFReadDirectory+0x9be>
  4127ab:	lea    0x1c2(%rbp),%rdx
  4127b2:	mov    %rbx,%rsi
  4127b5:	mov    %rbp,%rdi
  4127b8:	callq  411067 <TIFFFetchShortArray>
  4127bd:	test   %eax,%eax
  4127bf:	je     4124da <TIFFReadDirectory+0x9be>
  4127c5:	orq    $0x4000000,0x28(%rbp)
  4127cd:	jmpq   4124da <TIFFReadDirectory+0x9be>
  4127d2:	lea    0x30(%rsp),%rdx
  4127d7:	mov    %rbx,%rsi
  4127da:	mov    %rbp,%rdi
  4127dd:	callq  410f55 <TIFFFetchData>
  4127e2:	test   %eax,%eax
  4127e4:	jne    41255d <TIFFReadDirectory+0xa41>
  4127ea:	jmpq   4124da <TIFFReadDirectory+0x9be>
  4127ef:	lea    0x178(%rbp),%rdx
  4127f6:	mov    %rbx,%rsi
  4127f9:	mov    %rbp,%rdi
  4127fc:	callq  41133f <TIFFFetchJPEGCTables>
  412801:	test   %eax,%eax
  412803:	je     4124da <TIFFReadDirectory+0x9be>
  412809:	orq    $0x40000,0x28(%rbp)
  412811:	jmpq   4124da <TIFFReadDirectory+0x9be>
  412816:	lea    0x180(%rbp),%rdx
  41281d:	mov    %rbx,%rsi
  412820:	mov    %rbp,%rdi
  412823:	callq  41133f <TIFFFetchJPEGCTables>
  412828:	test   %eax,%eax
  41282a:	je     4124da <TIFFReadDirectory+0x9be>
  412830:	orq    $0x80000,0x28(%rbp)
  412838:	jmpq   4124da <TIFFReadDirectory+0x9be>
  41283d:	mov    $0x41a1c8,%esi
  412842:	mov    0x0(%rbp),%rdi
  412846:	mov    $0x0,%eax
  41284b:	callq  412a93 <TIFFError>
  412850:	jmpq   4124da <TIFFReadDirectory+0x9be>
  412855:	movzwl 0x2(%rbx),%edx
  412859:	mov    0x1e8(%rbp),%rax
  412860:	mov    (%rax,%rdx,4),%ecx
  412863:	mov    0x10(%rbx),%rax
  412867:	shr    %cl,%rax
  41286a:	mov    0x1f0(%rbp),%rcx
  412871:	and    (%rcx,%rdx,8),%eax
  412874:	jmpq   4122dc <TIFFReadDirectory+0x7c0>
  412879:	mov    $0x1,%edx
  41287e:	mov    $0x80e3,%esi
  412883:	mov    %rbp,%rdi
  412886:	mov    $0x0,%eax
  41288b:	callq  4105df <TIFFSetField>
  412890:	jmpq   4124da <TIFFReadDirectory+0x9be>
  412895:	movzwl 0x2(%rbx),%edx
  412899:	mov    0x1e8(%rbp),%rax
  4128a0:	mov    (%rax,%rdx,4),%ecx
  4128a3:	mov    0x10(%rbx),%rax
  4128a7:	shr    %cl,%rax
  4128aa:	mov    0x1f0(%rbp),%rcx
  4128b1:	and    (%rcx,%rdx,8),%rax
  4128b5:	jmpq   4121d6 <TIFFReadDirectory+0x6ba>
  4128ba:	cmpw   $0x3,0x68(%rbp)
  4128bf:	je     4128e3 <TIFFReadDirectory+0xdc7>
  4128c1:	testb  $0x4,0x23(%rbp)
  4128c5:	jne    41292e <TIFFReadDirectory+0xe12>
  4128c7:	cmpq   $0x1,0x140(%rbp)
  4128cf:	jbe    4128fb <TIFFReadDirectory+0xddf>
  4128d1:	mov    $0x419cb8,%esi
  4128d6:	mov    %rbp,%rdi
  4128d9:	callq  410ef0 <MissingRequired>
  4128de:	jmpq   41227d <TIFFReadDirectory+0x761>
  4128e3:	testb  $0x10,0x23(%rbp)
  4128e7:	jne    4128c1 <TIFFReadDirectory+0xda5>
  4128e9:	mov    $0x41a482,%esi
  4128ee:	mov    %rbp,%rdi
  4128f1:	callq  410ef0 <MissingRequired>
  4128f6:	jmpq   41227d <TIFFReadDirectory+0x761>
  4128fb:	mov    $0x117,%edi
  412900:	callq  410ebe <TIFFFieldWithTag>
  412905:	mov    0x10(%rax),%rdx
  412909:	mov    $0x41a228,%esi
  41290e:	mov    0x0(%rbp),%rdi
  412912:	mov    $0x0,%eax
  412917:	callq  413526 <TIFFWarning>
  41291c:	movzwl 0x5e(%rsp),%edx
  412921:	mov    %r14,%rsi
  412924:	mov    %rbp,%rdi
  412927:	callq  41145b <EstimateStripByteCounts>
  41292c:	jmp    412938 <TIFFReadDirectory+0xe1c>
  41292e:	cmpq   $0x1,0x140(%rbp)
  412936:	je     4129b7 <TIFFReadDirectory+0xe9b>
  412938:	test   %r14,%r14
  41293b:	je     412945 <TIFFReadDirectory+0xe29>
  41293d:	mov    %r14,%rdi
  412940:	callq  4010b0 <free@plt>
  412945:	mov    0x20(%rbp),%rax
  412949:	test   $0x80000,%eax
  41294e:	jne    412967 <TIFFReadDirectory+0xe4b>
  412950:	movzwl 0x62(%rbp),%ecx
  412954:	mov    $0x1,%edx
  412959:	shl    %cl,%rdx
  41295c:	sub    $0x1,%rdx
  412960:	mov    %rdx,0x88(%rbp)
  412967:	test   $0x80,%al
  412969:	je     4129fe <TIFFReadDirectory+0xee2>
  41296f:	mov    $0xffffffffffffffff,%rax
  412976:	mov    %rax,0x1f8(%rbp)
  41297d:	mov    %eax,0x204(%rbp)
  412983:	mov    %rax,0x210(%rbp)
  41298a:	mov    %eax,0x218(%rbp)
  412990:	mov    %rbp,%rdi
  412993:	callq  413493 <TIFFTileSize>
  412998:	mov    %rax,0x220(%rbp)
  41299f:	mov    %rbp,%rdi
  4129a2:	callq  412fcd <TIFFScanlineSize>
  4129a7:	mov    %eax,0x290(%rbp)
  4129ad:	mov    $0x1,%eax
  4129b2:	jmpq   411d3d <TIFFReadDirectory+0x221>
  4129b7:	mov    0x150(%rbp),%rax
  4129be:	cmpq   $0x0,(%rax)
  4129c2:	jne    412938 <TIFFReadDirectory+0xe1c>
  4129c8:	mov    $0x117,%edi
  4129cd:	callq  410ebe <TIFFFieldWithTag>
  4129d2:	mov    0x10(%rax),%rdx
  4129d6:	mov    $0x41a278,%esi
  4129db:	mov    0x0(%rbp),%rdi
  4129df:	mov    $0x0,%eax
  4129e4:	callq  413526 <TIFFWarning>
  4129e9:	movzwl 0x5e(%rsp),%edx
  4129ee:	mov    %r14,%rsi
  4129f1:	mov    %rbp,%rdi
  4129f4:	callq  41145b <EstimateStripByteCounts>
  4129f9:	jmpq   412938 <TIFFReadDirectory+0xe1c>
  4129fe:	mov    $0x1,%edx
  412a03:	mov    $0x103,%esi
  412a08:	mov    %rbp,%rdi
  412a0b:	mov    $0x0,%eax
  412a10:	callq  4105df <TIFFSetField>
  412a15:	jmpq   41296f <TIFFReadDirectory+0xe53>
  412a1a:	mov    $0x1,%edx
  412a1f:	jmpq   4121ef <TIFFReadDirectory+0x6d3>
  412a24:	repz retq 

0000000000412a26 <defaultHandler>:
  412a26:	push   %rbp
  412a27:	push   %rbx
  412a28:	sub    $0x8,%rsp
  412a2c:	mov    %rsi,%rbx
  412a2f:	mov    %rdx,%rbp
  412a32:	test   %rdi,%rdi
  412a35:	je     412a50 <defaultHandler+0x2a>
  412a37:	mov    %rdi,%rdx
  412a3a:	mov    $0x41a48b,%esi
  412a3f:	mov    0x22f75a(%rip),%rdi        # 6421a0 <stderr@@GLIBC_2.2.5>
  412a46:	mov    $0x0,%eax
  412a4b:	callq  401220 <fprintf@plt>
  412a50:	mov    %rbp,%rdx
  412a53:	mov    %rbx,%rsi
  412a56:	mov    0x22f743(%rip),%rdi        # 6421a0 <stderr@@GLIBC_2.2.5>
  412a5d:	callq  401310 <vfprintf@plt>
  412a62:	mov    0x22f737(%rip),%rcx        # 6421a0 <stderr@@GLIBC_2.2.5>
  412a69:	mov    $0x2,%edx
  412a6e:	mov    $0x1,%esi
  412a73:	mov    $0x41a490,%edi
  412a78:	callq  401350 <fwrite@plt>
  412a7d:	add    $0x8,%rsp
  412a81:	pop    %rbx
  412a82:	pop    %rbp
  412a83:	retq   

0000000000412a84 <TIFFSetErrorHandler>:
  412a84:	mov    0x20d075(%rip),%rax        # 61fb00 <_errorHandler>
  412a8b:	mov    %rdi,0x20d06e(%rip)        # 61fb00 <_errorHandler>
  412a92:	retq   

0000000000412a93 <TIFFError>:
  412a93:	sub    $0xd8,%rsp
  412a9a:	mov    %rdx,0x30(%rsp)
  412a9f:	mov    %rcx,0x38(%rsp)
  412aa4:	mov    %r8,0x40(%rsp)
  412aa9:	mov    %r9,0x48(%rsp)
  412aae:	test   %al,%al
  412ab0:	je     412ae9 <TIFFError+0x56>
  412ab2:	movaps %xmm0,0x50(%rsp)
  412ab7:	movaps %xmm1,0x60(%rsp)
  412abc:	movaps %xmm2,0x70(%rsp)
  412ac1:	movaps %xmm3,0x80(%rsp)
  412ac9:	movaps %xmm4,0x90(%rsp)
  412ad1:	movaps %xmm5,0xa0(%rsp)
  412ad9:	movaps %xmm6,0xb0(%rsp)
  412ae1:	movaps %xmm7,0xc0(%rsp)
  412ae9:	mov    0x20d010(%rip),%rax        # 61fb00 <_errorHandler>
  412af0:	test   %rax,%rax
  412af3:	je     412b23 <TIFFError+0x90>
  412af5:	movl   $0x10,0x8(%rsp)
  412afd:	movl   $0x30,0xc(%rsp)
  412b05:	lea    0xe0(%rsp),%rcx
  412b0d:	mov    %rcx,0x10(%rsp)
  412b12:	lea    0x20(%rsp),%rdx
  412b17:	mov    %rdx,0x18(%rsp)
  412b1c:	lea    0x8(%rsp),%rdx
  412b21:	callq  *%rax
  412b23:	add    $0xd8,%rsp
  412b2a:	retq   

0000000000412b2b <TIFFFlushData>:
  412b2b:	movzwl 0xe(%rdi),%edx
  412b2f:	mov    $0x0,%eax
  412b34:	test   $0x8,%dl
  412b37:	je     412b6a <TIFFFlushData+0x3f>
  412b39:	push   %rbx
  412b3a:	mov    %rdi,%rbx
  412b3d:	test   $0x2,%dh
  412b40:	je     412b5b <TIFFFlushData+0x30>
  412b42:	and    $0xfd,%dh
  412b45:	mov    %dx,0xe(%rdi)
  412b49:	mov    0x238(%rdi),%rdx
  412b50:	test   %rdx,%rdx
  412b53:	je     412b5b <TIFFFlushData+0x30>
  412b55:	callq  *%rdx
  412b57:	test   %eax,%eax
  412b59:	je     412b68 <TIFFFlushData+0x3d>
  412b5b:	mov    %rbx,%rdi
  412b5e:	mov    $0x0,%eax
  412b63:	callq  41425a <TIFFFlushData1>
  412b68:	pop    %rbx
  412b69:	retq   
  412b6a:	repz retq 

0000000000412b6c <TIFFFlush>:
  412b6c:	mov    $0x1,%eax
  412b71:	cmpw   $0x0,0xa(%rdi)
  412b76:	jne    412b7a <TIFFFlush+0xe>
  412b78:	repz retq 
  412b7a:	push   %rbx
  412b7b:	mov    %rdi,%rbx
  412b7e:	callq  412b2b <TIFFFlushData>
  412b83:	test   %eax,%eax
  412b85:	je     412b92 <TIFFFlush+0x26>
  412b87:	mov    $0x1,%eax
  412b8c:	testb  $0x2,0xe(%rbx)
  412b90:	jne    412b94 <TIFFFlush+0x28>
  412b92:	pop    %rbx
  412b93:	retq   
  412b94:	mov    %rbx,%rdi
  412b97:	callq  414911 <TIFFWriteDirectory>
  412b9c:	test   %eax,%eax
  412b9e:	setne  %al
  412ba1:	movzbl %al,%eax
  412ba4:	jmp    412b92 <TIFFFlush+0x26>

0000000000412ba6 <getMode>:
  412ba6:	movzbl (%rdi),%eax
  412ba9:	cmp    $0x72,%al
  412bab:	je     412bdb <getMode+0x35>
  412bad:	cmp    $0x77,%al
  412baf:	je     412be8 <getMode+0x42>
  412bb1:	cmp    $0x61,%al
  412bb3:	je     412be8 <getMode+0x42>
  412bb5:	sub    $0x8,%rsp
  412bb9:	mov    %rsi,%rax
  412bbc:	mov    %rdi,%rdx
  412bbf:	mov    $0x41a493,%esi
  412bc4:	mov    %rax,%rdi
  412bc7:	mov    $0x0,%eax
  412bcc:	callq  412a93 <TIFFError>
  412bd1:	mov    $0xffffffff,%eax
  412bd6:	add    $0x8,%rsp
  412bda:	retq   
  412bdb:	cmpb   $0x2b,0x1(%rdi)
  412bdf:	sete   %al
  412be2:	movzbl %al,%eax
  412be5:	add    %eax,%eax
  412be7:	retq   
  412be8:	cmp    $0x77,%al
  412bea:	mov    $0x42,%eax
  412bef:	mov    $0x242,%edx
  412bf4:	cmove  %edx,%eax
  412bf7:	retq   

0000000000412bf8 <TIFFFdOpen>:
  412bf8:	push   %r14
  412bfa:	push   %r13
  412bfc:	push   %r12
  412bfe:	push   %rbp
  412bff:	push   %rbx
  412c00:	mov    %edi,%r12d
  412c03:	mov    %rsi,%r13
  412c06:	mov    %rdx,%r14
  412c09:	mov    $0x61fb20,%esi
  412c0e:	mov    %rdx,%rdi
  412c11:	callq  412ba6 <getMode>
  412c16:	cmp    $0xffffffff,%eax
  412c19:	je     412d74 <TIFFFdOpen+0x17c>
  412c1f:	mov    %eax,%ebp
  412c21:	mov    $0xffffffffffffffff,%rcx
  412c28:	mov    $0x0,%eax
  412c2d:	mov    %r13,%rdi
  412c30:	repnz scas %es:(%rdi),%al
  412c32:	not    %rcx
  412c35:	lea    0x2c8(%rcx),%rdi
  412c3c:	callq  401270 <malloc@plt>
  412c41:	mov    %rax,%rbx
  412c44:	test   %rax,%rax
  412c47:	je     412d5d <TIFFFdOpen+0x165>
  412c4d:	mov    $0x2c8,%esi
  412c52:	mov    %rax,%rdi
  412c55:	mov    $0x0,%eax
  412c5a:	callq  4012f0 <bzero@plt>
  412c5f:	lea    0x2c8(%rbx),%rdi
  412c66:	mov    %rdi,(%rbx)
  412c69:	mov    %r13,%rsi
  412c6c:	callq  4010f0 <strcpy@plt>
  412c71:	mov    %r12w,0x8(%rbx)
  412c76:	and    $0xfdbf,%bp
  412c7b:	mov    %bp,0xa(%rbx)
  412c7f:	movl   $0xffffffff,0x200(%rbx)
  412c89:	movq   $0x0,0x208(%rbx)
  412c94:	movl   $0xffffffff,0x204(%rbx)
  412c9e:	movq   $0xffffffffffffffff,0x1f8(%rbx)
  412ca9:	lea    0x1d8(%rbx),%rbp
  412cb0:	mov    $0x10,%edx
  412cb5:	mov    %rbp,%rsi
  412cb8:	mov    %r12d,%edi
  412cbb:	mov    $0x0,%eax
  412cc0:	callq  401200 <read@plt>
  412cc5:	cmp    $0x10,%eax
  412cc8:	je     412dd8 <TIFFFdOpen+0x1e0>
  412cce:	cmpw   $0x0,0xa(%rbx)
  412cd3:	je     412d88 <TIFFFdOpen+0x190>
  412cd9:	movw   $0x4949,0x1d8(%rbx)
  412ce2:	movw   $0x2a,0x1da(%rbx)
  412ceb:	movq   $0x0,0x1e0(%rbx)
  412cf6:	mov    $0x10,%edx
  412cfb:	mov    %rbp,%rsi
  412cfe:	mov    %r12d,%edi
  412d01:	mov    $0x0,%eax
  412d06:	callq  401120 <write@plt>
  412d0b:	cmp    $0x10,%eax
  412d0e:	jne    412d9c <TIFFFdOpen+0x1a4>
  412d14:	movb   $0x1,0xc(%rbx)
  412d18:	movq   $0x61fb80,0x1f0(%rbx)
  412d23:	cmpw   $0x4d4d,0x1d8(%rbx)
  412d2c:	je     412dc3 <TIFFFdOpen+0x1cb>
  412d32:	movq   $0x6421c0,0x1e8(%rbx)
  412d3d:	mov    %rbx,%rdi
  412d40:	callq  410c5b <TIFFDefaultDirectory>
  412d45:	test   %eax,%eax
  412d47:	je     412dae <TIFFFdOpen+0x1b6>
  412d49:	movq   $0x0,0x10(%rbx)
  412d51:	mov    %rbx,%rax
  412d54:	pop    %rbx
  412d55:	pop    %rbp
  412d56:	pop    %r12
  412d58:	pop    %r13
  412d5a:	pop    %r14
  412d5c:	retq   
  412d5d:	mov    %r13,%rdx
  412d60:	mov    $0x41a4e8,%esi
  412d65:	mov    $0x61fb20,%edi
  412d6a:	mov    $0x0,%eax
  412d6f:	callq  412a93 <TIFFError>
  412d74:	mov    %r12d,%edi
  412d77:	mov    $0x0,%eax
  412d7c:	callq  4011f0 <close@plt>
  412d81:	mov    $0x0,%ebx
  412d86:	jmp    412d51 <TIFFFdOpen+0x159>
  412d88:	mov    $0x41a4a2,%esi
  412d8d:	mov    %r13,%rdi
  412d90:	mov    $0x0,%eax
  412d95:	callq  412a93 <TIFFError>
  412d9a:	jmp    412dae <TIFFFdOpen+0x1b6>
  412d9c:	mov    $0x41a4ba,%esi
  412da1:	mov    %r13,%rdi
  412da4:	mov    $0x0,%eax
  412da9:	callq  412a93 <TIFFError>
  412dae:	movw   $0x0,0xa(%rbx)
  412db4:	mov    %rbx,%rdi
  412db7:	callq  40da67 <TIFFClose>
  412dbc:	mov    $0x0,%ebx
  412dc1:	jmp    412d51 <TIFFFdOpen+0x159>
  412dc3:	movq   $0x61fb40,0x1e8(%rbx)
  412dce:	orw    $0x10,0xe(%rbx)
  412dd3:	jmpq   412d3d <TIFFFdOpen+0x145>
  412dd8:	movzwl 0x1d8(%rbx),%edx
  412ddf:	cmp    $0x4d4d,%dx
  412de4:	je     412df1 <TIFFFdOpen+0x1f9>
  412de6:	cmp    $0x4949,%dx
  412deb:	jne    412ec3 <TIFFFdOpen+0x2cb>
  412df1:	movb   $0x1,0xc(%rbx)
  412df5:	movq   $0x61fb80,0x1f0(%rbx)
  412e00:	cmp    $0x4d4d,%dx
  412e05:	je     412edf <TIFFFdOpen+0x2e7>
  412e0b:	movq   $0x6421c0,0x1e8(%rbx)
  412e16:	testb  $0x10,0xe(%rbx)
  412e1a:	jne    412ef4 <TIFFFdOpen+0x2fc>
  412e20:	movzwl 0x1da(%rbx),%edx
  412e27:	cmp    $0x2a,%dx
  412e2b:	jne    412f11 <TIFFFdOpen+0x319>
  412e31:	movzwl 0xe(%rbx),%edx
  412e35:	mov    %edx,%eax
  412e37:	or     $0x40,%eax
  412e3a:	mov    %ax,0xe(%rbx)
  412e3e:	movq   $0x0,0x298(%rbx)
  412e49:	movq   $0x0,0x2a8(%rbx)
  412e54:	movq   $0x0,0x2a0(%rbx)
  412e5f:	movzbl (%r14),%eax
  412e63:	cmp    $0x61,%al
  412e65:	je     412f2d <TIFFFdOpen+0x335>
  412e6b:	cmp    $0x72,%al
  412e6d:	jne    412dae <TIFFFdOpen+0x1b6>
  412e73:	mov    0x1e0(%rbx),%rax
  412e7a:	mov    %rax,0x18(%rbx)
  412e7e:	lea    0x2c0(%rbx),%rdx
  412e85:	lea    0x2b8(%rbx),%rsi
  412e8c:	mov    %r12d,%edi
  412e8f:	callq  40db12 <TIFFMapFileContents>
  412e94:	test   %eax,%eax
  412e96:	je     412e9e <TIFFFdOpen+0x2a6>
  412e98:	orw    $0x100,0xe(%rbx)
  412e9e:	mov    %rbx,%rdi
  412ea1:	callq  411b1c <TIFFReadDirectory>
  412ea6:	test   %eax,%eax
  412ea8:	je     412dae <TIFFFdOpen+0x1b6>
  412eae:	movq   $0xffffffffffffffff,0x2b0(%rbx)
  412eb9:	orw    $0x4,0xe(%rbx)
  412ebe:	jmpq   412d51 <TIFFFdOpen+0x159>
  412ec3:	movzwl %dx,%edx
  412ec6:	mov    %edx,%ecx
  412ec8:	mov    $0x41a510,%esi
  412ecd:	mov    %r13,%rdi
  412ed0:	mov    $0x0,%eax
  412ed5:	callq  412a93 <TIFFError>
  412eda:	jmpq   412dae <TIFFFdOpen+0x1b6>
  412edf:	movq   $0x61fb40,0x1e8(%rbx)
  412eea:	orw    $0x10,0xe(%rbx)
  412eef:	jmpq   412e16 <TIFFFdOpen+0x21e>
  412ef4:	lea    0x1da(%rbx),%rdi
  412efb:	callq  413028 <TIFFSwabShort>
  412f00:	lea    0x1e0(%rbx),%rdi
  412f07:	callq  413035 <TIFFSwabLong>
  412f0c:	jmpq   412e20 <TIFFFdOpen+0x228>
  412f11:	movzwl %dx,%edx
  412f14:	mov    %edx,%ecx
  412f16:	mov    $0x41a540,%esi
  412f1b:	mov    %r13,%rdi
  412f1e:	mov    $0x0,%eax
  412f23:	callq  412a93 <TIFFError>
  412f28:	jmpq   412dae <TIFFFdOpen+0x1b6>
  412f2d:	test   $0x10,%dl
  412f30:	jne    412f47 <TIFFFdOpen+0x34f>
  412f32:	mov    %rbx,%rdi
  412f35:	callq  410c5b <TIFFDefaultDirectory>
  412f3a:	test   %eax,%eax
  412f3c:	jne    412d51 <TIFFFdOpen+0x159>
  412f42:	jmpq   412dae <TIFFFdOpen+0x1b6>
  412f47:	mov    $0x41a570,%esi
  412f4c:	mov    %r13,%rdi
  412f4f:	mov    $0x0,%eax
  412f54:	callq  412a93 <TIFFError>
  412f59:	jmpq   412dae <TIFFFdOpen+0x1b6>

0000000000412f5e <TIFFOpen>:
  412f5e:	push   %rbp
  412f5f:	push   %rbx
  412f60:	sub    $0x8,%rsp
  412f64:	mov    %rdi,%rbp
  412f67:	mov    %rsi,%rbx
  412f6a:	mov    $0x61fb30,%esi
  412f6f:	mov    %rbx,%rdi
  412f72:	callq  412ba6 <getMode>
  412f77:	cmp    $0xffffffff,%eax
  412f7a:	je     412fc6 <TIFFOpen+0x68>
  412f7c:	mov    $0x1b6,%edx
  412f81:	mov    %eax,%esi
  412f83:	mov    %rbp,%rdi
  412f86:	mov    $0x0,%eax
  412f8b:	callq  4012e0 <open@plt>
  412f90:	test   %eax,%eax
  412f92:	js     412fa8 <TIFFOpen+0x4a>
  412f94:	mov    %rbx,%rdx
  412f97:	mov    %rbp,%rsi
  412f9a:	mov    %eax,%edi
  412f9c:	callq  412bf8 <TIFFFdOpen>
  412fa1:	add    $0x8,%rsp
  412fa5:	pop    %rbx
  412fa6:	pop    %rbp
  412fa7:	retq   
  412fa8:	mov    %rbp,%rdx
  412fab:	mov    $0x41a4d4,%esi
  412fb0:	mov    $0x61fb30,%edi
  412fb5:	mov    $0x0,%eax
  412fba:	callq  412a93 <TIFFError>
  412fbf:	mov    $0x0,%eax
  412fc4:	jmp    412fa1 <TIFFOpen+0x43>
  412fc6:	mov    $0x0,%eax
  412fcb:	jmp    412fa1 <TIFFOpen+0x43>

0000000000412fcd <TIFFScanlineSize>:
  412fcd:	movzwl 0x62(%rdi),%eax
  412fd1:	imul   0x30(%rdi),%rax
  412fd6:	cmpw   $0x1,0x9a(%rdi)
  412fde:	je     412fe7 <TIFFScanlineSize+0x1a>
  412fe0:	add    $0x7,%eax
  412fe3:	shr    $0x3,%eax
  412fe6:	retq   
  412fe7:	movzwl 0x70(%rdi),%edx
  412feb:	imul   %rdx,%rax
  412fef:	jmp    412fe0 <TIFFScanlineSize+0x13>

0000000000412ff1 <TIFFFileName>:
  412ff1:	mov    (%rdi),%rax
  412ff4:	retq   

0000000000412ff5 <TIFFFileno>:
  412ff5:	movswl 0x8(%rdi),%eax
  412ff9:	retq   

0000000000412ffa <TIFFGetMode>:
  412ffa:	movswl 0xa(%rdi),%eax
  412ffe:	retq   

0000000000412fff <TIFFIsTiled>:
  412fff:	movzwl 0xe(%rdi),%eax
  413003:	shr    $0x7,%ax
  413007:	and    $0x1,%eax
  41300a:	retq   

000000000041300b <TIFFCurrentRow>:
  41300b:	mov    0x1f8(%rdi),%rax
  413012:	retq   

0000000000413013 <TIFFCurrentDirectory>:
  413013:	mov    0x200(%rdi),%eax
  413019:	retq   

000000000041301a <TIFFCurrentStrip>:
  41301a:	mov    0x204(%rdi),%eax
  413020:	retq   

0000000000413021 <TIFFCurrentTile>:
  413021:	mov    0x218(%rdi),%eax
  413027:	retq   

0000000000413028 <TIFFSwabShort>:
  413028:	movzbl 0x1(%rdi),%eax
  41302c:	movzbl (%rdi),%edx
  41302f:	mov    %dl,0x1(%rdi)
  413032:	mov    %al,(%rdi)
  413034:	retq   

0000000000413035 <TIFFSwabLong>:
  413035:	movzbl 0x3(%rdi),%eax
  413039:	movzbl (%rdi),%edx
  41303c:	mov    %dl,0x3(%rdi)
  41303f:	mov    %al,(%rdi)
  413041:	movzbl 0x2(%rdi),%eax
  413045:	movzbl 0x1(%rdi),%edx
  413049:	mov    %dl,0x2(%rdi)
  41304c:	mov    %al,0x1(%rdi)
  41304f:	retq   

0000000000413050 <TIFFSwabArrayOfShort>:
  413050:	test   %esi,%esi
  413052:	jle    413071 <TIFFSwabArrayOfShort+0x21>
  413054:	lea    -0x1(%rsi),%eax
  413057:	lea    0x2(%rdi,%rax,2),%rcx
  41305c:	movzbl 0x1(%rdi),%eax
  413060:	movzbl (%rdi),%edx
  413063:	mov    %dl,0x1(%rdi)
  413066:	mov    %al,(%rdi)
  413068:	add    $0x2,%rdi
  41306c:	cmp    %rcx,%rdi
  41306f:	jne    41305c <TIFFSwabArrayOfShort+0xc>
  413071:	repz retq 

0000000000413073 <TIFFSwabArrayOfLong>:
  413073:	test   %esi,%esi
  413075:	jle    4130a2 <TIFFSwabArrayOfLong+0x2f>
  413077:	lea    -0x1(%rsi),%eax
  41307a:	lea    0x8(%rdi,%rax,8),%rcx
  41307f:	movzbl 0x3(%rdi),%eax
  413083:	movzbl (%rdi),%edx
  413086:	mov    %dl,0x3(%rdi)
  413089:	mov    %al,(%rdi)
  41308b:	movzbl 0x2(%rdi),%eax
  41308f:	movzbl 0x1(%rdi),%edx
  413093:	mov    %dl,0x2(%rdi)
  413096:	mov    %al,0x1(%rdi)
  413099:	add    $0x8,%rdi
  41309d:	cmp    %rcx,%rdi
  4130a0:	jne    41307f <TIFFSwabArrayOfLong+0xc>
  4130a2:	repz retq 

00000000004130a4 <TIFFReverseBits>:
  4130a4:	cmp    $0x8,%esi
  4130a7:	jle    413137 <TIFFReverseBits+0x93>
  4130ad:	lea    -0x9(%rsi),%ecx
  4130b0:	shr    $0x3,%ecx
  4130b3:	mov    %ecx,%eax
  4130b5:	lea    0x8(%rdi,%rax,8),%rdx
  4130ba:	movzbl (%rdi),%eax
  4130bd:	movzbl 0x41a6c0(%rax),%eax
  4130c4:	mov    %al,(%rdi)
  4130c6:	movzbl 0x1(%rdi),%eax
  4130ca:	movzbl 0x41a6c0(%rax),%eax
  4130d1:	mov    %al,0x1(%rdi)
  4130d4:	movzbl 0x2(%rdi),%eax
  4130d8:	movzbl 0x41a6c0(%rax),%eax
  4130df:	mov    %al,0x2(%rdi)
  4130e2:	movzbl 0x3(%rdi),%eax
  4130e6:	movzbl 0x41a6c0(%rax),%eax
  4130ed:	mov    %al,0x3(%rdi)
  4130f0:	movzbl 0x4(%rdi),%eax
  4130f4:	movzbl 0x41a6c0(%rax),%eax
  4130fb:	mov    %al,0x4(%rdi)
  4130fe:	movzbl 0x5(%rdi),%eax
  413102:	movzbl 0x41a6c0(%rax),%eax
  413109:	mov    %al,0x5(%rdi)
  41310c:	movzbl 0x6(%rdi),%eax
  413110:	movzbl 0x41a6c0(%rax),%eax
  413117:	mov    %al,0x6(%rdi)
  41311a:	movzbl 0x7(%rdi),%eax
  41311e:	movzbl 0x41a6c0(%rax),%eax
  413125:	mov    %al,0x7(%rdi)
  413128:	add    $0x8,%rdi
  41312c:	cmp    %rdx,%rdi
  41312f:	jne    4130ba <TIFFReverseBits+0x16>
  413131:	neg    %ecx
  413133:	lea    -0x8(%rsi,%rcx,8),%esi
  413137:	test   %esi,%esi
  413139:	jle    413158 <TIFFReverseBits+0xb4>
  41313b:	lea    -0x1(%rsi),%eax
  41313e:	lea    0x1(%rdi,%rax,1),%rdx
  413143:	movzbl (%rdi),%eax
  413146:	movzbl 0x41a6c0(%rax),%eax
  41314d:	mov    %al,(%rdi)
  41314f:	add    $0x1,%rdi
  413153:	cmp    %rdx,%rdi
  413156:	jne    413143 <TIFFReverseBits+0x9f>
  413158:	repz retq 

000000000041315a <TIFFComputeTile>:
  41315a:	push   %r13
  41315c:	push   %r12
  41315e:	push   %rbp
  41315f:	push   %rbx
  413160:	mov    %rdx,%rbp
  413163:	mov    0x48(%rdi),%r10
  413167:	mov    0x50(%rdi),%r11
  41316b:	mov    0x58(%rdi),%r9
  41316f:	mov    0x40(%rdi),%r13
  413173:	cmp    $0x1,%r13
  413177:	mov    $0x0,%eax
  41317c:	cmove  %rax,%r8
  413180:	cmp    $0xffffffffffffffff,%r10
  413184:	je     4131b5 <TIFFComputeTile+0x5b>
  413186:	cmp    $0xffffffffffffffff,%r11
  41318a:	je     4131bb <TIFFComputeTile+0x61>
  41318c:	cmp    $0xffffffffffffffff,%r9
  413190:	cmove  %r13,%r9
  413194:	test   %r10,%r10
  413197:	setne  %dl
  41319a:	test   %r11,%r11
  41319d:	setne  %al
  4131a0:	test   %al,%dl
  4131a2:	je     4131a9 <TIFFComputeTile+0x4f>
  4131a4:	test   %r9,%r9
  4131a7:	jne    4131c1 <TIFFComputeTile+0x67>
  4131a9:	mov    $0x1,%eax
  4131ae:	pop    %rbx
  4131af:	pop    %rbp
  4131b0:	pop    %r12
  4131b2:	pop    %r13
  4131b4:	retq   
  4131b5:	mov    0x30(%rdi),%r10
  4131b9:	jmp    413186 <TIFFComputeTile+0x2c>
  4131bb:	mov    0x38(%rdi),%r11
  4131bf:	jmp    41318c <TIFFComputeTile+0x32>
  4131c1:	mov    0x30(%rdi),%rax
  4131c5:	lea    -0x1(%rax,%r10,1),%eax
  4131ca:	mov    $0x0,%edx
  4131cf:	div    %r10d
  4131d2:	mov    %eax,%r12d
  4131d5:	mov    0x38(%rdi),%rax
  4131d9:	lea    -0x1(%rax,%r11,1),%eax
  4131de:	mov    $0x0,%edx
  4131e3:	div    %r11d
  4131e6:	mov    %eax,%ebx
  4131e8:	cmpw   $0x2,0x9a(%rdi)
  4131f0:	je     41322b <TIFFComputeTile+0xd1>
  4131f2:	mov    %r8,%rax
  4131f5:	mov    $0x0,%edx
  4131fa:	div    %r9
  4131fd:	mov    %rax,%r8
  413200:	imul   %ebx,%r8d
  413204:	mov    %rbp,%rax
  413207:	mov    $0x0,%edx
  41320c:	div    %r11
  41320f:	add    %r8d,%eax
  413212:	imul   %r12d,%eax
  413216:	mov    %eax,%r8d
  413219:	mov    %rsi,%rax
  41321c:	mov    $0x0,%edx
  413221:	div    %r10
  413224:	add    %ecx,%eax
  413226:	add    %r8d,%eax
  413229:	jmp    4131ae <TIFFComputeTile+0x54>
  41322b:	lea    -0x1(%r13,%r9,1),%eax
  413230:	mov    $0x0,%edx
  413235:	div    %r9d
  413238:	imul   %eax,%ecx
  41323b:	mov    %r8,%rax
  41323e:	mov    $0x0,%edx
  413243:	div    %r9
  413246:	mov    %rax,%r8
  413249:	add    %ecx,%r8d
  41324c:	imul   %r8d,%ebx
  413250:	mov    %rbp,%rax
  413253:	mov    $0x0,%edx
  413258:	div    %r11
  41325b:	add    %ebx,%eax
  41325d:	imul   %r12d,%eax
  413261:	mov    %eax,%r8d
  413264:	mov    %rsi,%rax
  413267:	mov    $0x0,%edx
  41326c:	div    %r10
  41326f:	add    %r8d,%eax
  413272:	jmpq   4131ae <TIFFComputeTile+0x54>

0000000000413277 <TIFFCheckTile>:
  413277:	sub    $0x8,%rsp
  41327b:	mov    %rcx,%rax
  41327e:	mov    0x30(%rdi),%rcx
  413282:	cmp    %rsi,%rcx
  413285:	jbe    4132d2 <TIFFCheckTile+0x5b>
  413287:	mov    0x38(%rdi),%rcx
  41328b:	cmp    %rdx,%rcx
  41328e:	jbe    4132f1 <TIFFCheckTile+0x7a>
  413290:	mov    0x40(%rdi),%rcx
  413294:	cmp    %rax,%rcx
  413297:	jbe    41330a <TIFFCheckTile+0x93>
  413299:	mov    $0x1,%eax
  41329e:	cmpw   $0x2,0x9a(%rdi)
  4132a6:	jne    4132ec <TIFFCheckTile+0x75>
  4132a8:	movzwl 0x70(%rdi),%ecx
  4132ac:	movzwl %cx,%edx
  4132af:	cmp    %r8d,%edx
  4132b2:	ja     4132ec <TIFFCheckTile+0x75>
  4132b4:	mov    %edx,%ecx
  4132b6:	mov    %r8d,%edx
  4132b9:	mov    $0x41a818,%esi
  4132be:	mov    (%rdi),%rdi
  4132c1:	mov    $0x0,%eax
  4132c6:	callq  412a93 <TIFFError>
  4132cb:	mov    $0x0,%eax
  4132d0:	jmp    4132ec <TIFFCheckTile+0x75>
  4132d2:	mov    %rsi,%rdx
  4132d5:	mov    $0x41a7c0,%esi
  4132da:	mov    (%rdi),%rdi
  4132dd:	mov    $0x0,%eax
  4132e2:	callq  412a93 <TIFFError>
  4132e7:	mov    $0x0,%eax
  4132ec:	add    $0x8,%rsp
  4132f0:	retq   
  4132f1:	mov    $0x41a7dc,%esi
  4132f6:	mov    (%rdi),%rdi
  4132f9:	mov    $0x0,%eax
  4132fe:	callq  412a93 <TIFFError>
  413303:	mov    $0x0,%eax
  413308:	jmp    4132ec <TIFFCheckTile+0x75>
  41330a:	mov    %rax,%rdx
  41330d:	mov    $0x41a7f8,%esi
  413312:	mov    (%rdi),%rdi
  413315:	mov    $0x0,%eax
  41331a:	callq  412a93 <TIFFError>
  41331f:	mov    $0x0,%eax
  413324:	jmp    4132ec <TIFFCheckTile+0x75>

0000000000413326 <TIFFNumberOfTiles>:
  413326:	mov    0x48(%rdi),%rsi
  41332a:	mov    0x50(%rdi),%rcx
  41332e:	mov    0x58(%rdi),%r8
  413332:	cmp    $0xffffffffffffffff,%rsi
  413336:	je     41335f <TIFFNumberOfTiles+0x39>
  413338:	cmp    $0xffffffffffffffff,%rcx
  41333c:	je     413365 <TIFFNumberOfTiles+0x3f>
  41333e:	cmp    $0xffffffffffffffff,%r8
  413342:	je     41336b <TIFFNumberOfTiles+0x45>
  413344:	test   %rsi,%rsi
  413347:	setne  %dl
  41334a:	test   %rcx,%rcx
  41334d:	setne  %al
  413350:	test   %al,%dl
  413352:	je     413359 <TIFFNumberOfTiles+0x33>
  413354:	test   %r8,%r8
  413357:	jne    413371 <TIFFNumberOfTiles+0x4b>
  413359:	mov    $0x0,%eax
  41335e:	retq   
  41335f:	mov    0x30(%rdi),%rsi
  413363:	jmp    413338 <TIFFNumberOfTiles+0x12>
  413365:	mov    0x38(%rdi),%rcx
  413369:	jmp    41333e <TIFFNumberOfTiles+0x18>
  41336b:	mov    0x40(%rdi),%r8
  41336f:	jmp    413344 <TIFFNumberOfTiles+0x1e>
  413371:	mov    0x30(%rdi),%rax
  413375:	lea    -0x1(%rax,%rsi,1),%eax
  413379:	mov    $0x0,%edx
  41337e:	div    %esi
  413380:	mov    %eax,%esi
  413382:	mov    0x38(%rdi),%rax
  413386:	lea    -0x1(%rax,%rcx,1),%eax
  41338a:	mov    $0x0,%edx
  41338f:	div    %ecx
  413391:	mov    %esi,%ecx
  413393:	imul   %eax,%ecx
  413396:	mov    0x40(%rdi),%rax
  41339a:	lea    -0x1(%rax,%r8,1),%eax
  41339f:	mov    $0x0,%edx
  4133a4:	div    %r8d
  4133a7:	imul   %ecx,%eax
  4133aa:	retq   

00000000004133ab <TIFFTileRowSize>:
  4133ab:	mov    $0x0,%eax
  4133b0:	cmpq   $0x0,0x50(%rdi)
  4133b5:	je     4133da <TIFFTileRowSize+0x2f>
  4133b7:	mov    0x48(%rdi),%rdx
  4133bb:	test   %rdx,%rdx
  4133be:	je     4133da <TIFFTileRowSize+0x2f>
  4133c0:	movzwl 0x62(%rdi),%eax
  4133c4:	imul   %rdx,%rax
  4133c8:	cmpw   $0x1,0x9a(%rdi)
  4133d0:	je     4133dc <TIFFTileRowSize+0x31>
  4133d2:	add    $0x7,%eax
  4133d5:	shr    $0x3,%eax
  4133d8:	mov    %eax,%eax
  4133da:	repz retq 
  4133dc:	movzwl 0x70(%rdi),%edx
  4133e0:	imul   %rdx,%rax
  4133e4:	jmp    4133d2 <TIFFTileRowSize+0x27>

00000000004133e6 <TIFFVTileSize>:
  4133e6:	mov    $0x0,%eax
  4133eb:	cmpq   $0x0,0x50(%rdi)
  4133f0:	je     413491 <TIFFVTileSize+0xab>
  4133f6:	mov    0x48(%rdi),%rcx
  4133fa:	test   %rcx,%rcx
  4133fd:	je     413491 <TIFFVTileSize+0xab>
  413403:	push   %rbp
  413404:	push   %rbx
  413405:	mov    0x58(%rdi),%rbx
  413409:	test   %rbx,%rbx
  41340c:	je     413428 <TIFFVTileSize+0x42>
  41340e:	cmpw   $0x1,0x9a(%rdi)
  413416:	je     41342b <TIFFVTileSize+0x45>
  413418:	mov    %rsi,%rbp
  41341b:	callq  4133ab <TIFFTileRowSize>
  413420:	imul   %rbp,%rax
  413424:	imul   %rbx,%rax
  413428:	pop    %rbx
  413429:	pop    %rbp
  41342a:	retq   
  41342b:	cmpw   $0x6,0x68(%rdi)
  413430:	jne    413418 <TIFFVTileSize+0x32>
  413432:	movzwl 0x160(%rdi),%r8d
  41343a:	movzwl 0x162(%rdi),%r9d
  413442:	lea    -0x1(%r9,%rsi,1),%eax
  413447:	mov    $0x0,%edx
  41344c:	div    %r9d
  41344f:	mov    %eax,%esi
  413451:	lea    -0x1(%r8,%rcx,1),%eax
  413456:	mov    $0x0,%edx
  41345b:	div    %r8d
  41345e:	movzwl 0x62(%rdi),%ecx
  413462:	imul   %r8d,%ecx
  413466:	imul   %ecx,%eax
  413469:	lea    0x7(%rax),%ecx
  41346c:	shr    $0x3,%ecx
  41346f:	mov    %ecx,%ecx
  413471:	imul   %r9d,%esi
  413475:	imul   %rsi,%rcx
  413479:	imul   %r9d,%r8d
  41347d:	movslq %r8d,%r8
  413480:	mov    %rcx,%rax
  413483:	mov    $0x0,%edx
  413488:	div    %r8
  41348b:	lea    (%rcx,%rax,2),%rax
  41348f:	jmp    413424 <TIFFVTileSize+0x3e>
  413491:	repz retq 

0000000000413493 <TIFFTileSize>:
  413493:	mov    0x50(%rdi),%rsi
  413497:	callq  4133e6 <TIFFVTileSize>
  41349c:	repz retq 

000000000041349e <defaultHandler>:
  41349e:	push   %rbp
  41349f:	push   %rbx
  4134a0:	sub    $0x8,%rsp
  4134a4:	mov    %rsi,%rbx
  4134a7:	mov    %rdx,%rbp
  4134aa:	test   %rdi,%rdi
  4134ad:	je     4134c8 <defaultHandler+0x2a>
  4134af:	mov    %rdi,%rdx
  4134b2:	mov    $0x41a48b,%esi
  4134b7:	mov    0x22ece2(%rip),%rdi        # 6421a0 <stderr@@GLIBC_2.2.5>
  4134be:	mov    $0x0,%eax
  4134c3:	callq  401220 <fprintf@plt>
  4134c8:	mov    0x22ecd1(%rip),%rcx        # 6421a0 <stderr@@GLIBC_2.2.5>
  4134cf:	mov    $0x9,%edx
  4134d4:	mov    $0x1,%esi
  4134d9:	mov    $0x41a837,%edi
  4134de:	callq  401350 <fwrite@plt>
  4134e3:	mov    %rbp,%rdx
  4134e6:	mov    %rbx,%rsi
  4134e9:	mov    0x22ecb0(%rip),%rdi        # 6421a0 <stderr@@GLIBC_2.2.5>
  4134f0:	callq  401310 <vfprintf@plt>
  4134f5:	mov    0x22eca4(%rip),%rcx        # 6421a0 <stderr@@GLIBC_2.2.5>
  4134fc:	mov    $0x2,%edx
  413501:	mov    $0x1,%esi
  413506:	mov    $0x41a490,%edi
  41350b:	callq  401350 <fwrite@plt>
  413510:	add    $0x8,%rsp
  413514:	pop    %rbx
  413515:	pop    %rbp
  413516:	retq   

0000000000413517 <TIFFSetWarningHandler>:
  413517:	mov    0x20c6ca(%rip),%rax        # 61fbe8 <_warningHandler>
  41351e:	mov    %rdi,0x20c6c3(%rip)        # 61fbe8 <_warningHandler>
  413525:	retq   

0000000000413526 <TIFFWarning>:
  413526:	sub    $0xd8,%rsp
  41352d:	mov    %rdx,0x30(%rsp)
  413532:	mov    %rcx,0x38(%rsp)
  413537:	mov    %r8,0x40(%rsp)
  41353c:	mov    %r9,0x48(%rsp)
  413541:	test   %al,%al
  413543:	je     41357c <TIFFWarning+0x56>
  413545:	movaps %xmm0,0x50(%rsp)
  41354a:	movaps %xmm1,0x60(%rsp)
  41354f:	movaps %xmm2,0x70(%rsp)
  413554:	movaps %xmm3,0x80(%rsp)
  41355c:	movaps %xmm4,0x90(%rsp)
  413564:	movaps %xmm5,0xa0(%rsp)
  41356c:	movaps %xmm6,0xb0(%rsp)
  413574:	movaps %xmm7,0xc0(%rsp)
  41357c:	mov    0x20c665(%rip),%rax        # 61fbe8 <_warningHandler>
  413583:	test   %rax,%rax
  413586:	je     4135b6 <TIFFWarning+0x90>
  413588:	movl   $0x10,0x8(%rsp)
  413590:	movl   $0x30,0xc(%rsp)
  413598:	lea    0xe0(%rsp),%rcx
  4135a0:	mov    %rcx,0x10(%rsp)
  4135a5:	lea    0x20(%rsp),%rdx
  4135aa:	mov    %rdx,0x18(%rsp)
  4135af:	lea    0x8(%rsp),%rdx
  4135b4:	callq  *%rax
  4135b6:	add    $0xd8,%rsp
  4135bd:	retq   

00000000004135be <TIFFWriteCheck>:
  4135be:	push   %rbp
  4135bf:	push   %rbx
  4135c0:	sub    $0x8,%rsp
  4135c4:	mov    %rdi,%rbx
  4135c7:	mov    %rdx,%rbp
  4135ca:	cmpw   $0x0,0xa(%rdi)
  4135cf:	je     41360f <TIFFWriteCheck+0x51>
  4135d1:	movzwl 0xe(%rdi),%edx
  4135d5:	mov    %edx,%ecx
  4135d7:	and    $0x80,%cx
  4135dc:	setne  %al
  4135df:	movzbl %al,%eax
  4135e2:	cmp    %esi,%eax
  4135e4:	je     41362b <TIFFWriteCheck+0x6d>
  4135e6:	test   %esi,%esi
  4135e8:	mov    $0x41a848,%esi
  4135ed:	mov    $0x41a870,%eax
  4135f2:	cmove  %rax,%rsi
  4135f6:	mov    (%rdi),%rdi
  4135f9:	mov    $0x0,%eax
  4135fe:	callq  412a93 <TIFFError>
  413603:	mov    $0x0,%eax
  413608:	add    $0x8,%rsp
  41360c:	pop    %rbx
  41360d:	pop    %rbp
  41360e:	retq   
  41360f:	mov    (%rdi),%rdx
  413612:	mov    $0x41aa84,%esi
  413617:	mov    %rbp,%rdi
  41361a:	mov    $0x0,%eax
  41361f:	callq  412a93 <TIFFError>
  413624:	mov    $0x0,%eax
  413629:	jmp    413608 <TIFFWriteCheck+0x4a>
  41362b:	mov    $0x1,%eax
  413630:	test   $0x8,%dl
  413633:	jne    413608 <TIFFWriteCheck+0x4a>
  413635:	mov    0x20(%rdi),%rax
  413639:	test   $0x1,%al
  41363b:	je     41365a <TIFFWriteCheck+0x9c>
  41363d:	test   $0x100000,%eax
  413642:	je     413676 <TIFFWriteCheck+0xb8>
  413644:	cmpq   $0x0,0x148(%rdi)
  41364c:	je     413695 <TIFFWriteCheck+0xd7>
  41364e:	orw    $0x8,0xe(%rbx)
  413653:	mov    $0x1,%eax
  413658:	jmp    413608 <TIFFWriteCheck+0x4a>
  41365a:	mov    (%rdi),%rdx
  41365d:	mov    $0x41a8a0,%esi
  413662:	mov    %rbp,%rdi
  413665:	mov    $0x0,%eax
  41366a:	callq  412a93 <TIFFError>
  41366f:	mov    $0x0,%eax
  413674:	jmp    413608 <TIFFWriteCheck+0x4a>
  413676:	mov    (%rdi),%rdx
  413679:	mov    $0x41a8d0,%esi
  41367e:	mov    %rbp,%rdi
  413681:	mov    $0x0,%eax
  413686:	callq  412a93 <TIFFError>
  41368b:	mov    $0x0,%eax
  413690:	jmpq   413608 <TIFFWriteCheck+0x4a>
  413695:	test   %cx,%cx
  413698:	jne    413789 <TIFFWriteCheck+0x1cb>
  41369e:	mov    0x78(%rdi),%rcx
  4136a2:	mov    $0x1,%eax
  4136a7:	mov    $0xffffffff,%edx
  4136ac:	cmp    %rdx,%rcx
  4136af:	je     4136c7 <TIFFWriteCheck+0x109>
  4136b1:	mov    0x38(%rdi),%rdx
  4136b5:	test   %rdx,%rdx
  4136b8:	je     4136c7 <TIFFWriteCheck+0x109>
  4136ba:	lea    -0x1(%rcx,%rdx,1),%eax
  4136be:	mov    $0x0,%edx
  4136c3:	div    %ecx
  4136c5:	mov    %eax,%eax
  4136c7:	mov    %rax,0x138(%rbx)
  4136ce:	mov    0x138(%rbx),%rax
  4136d5:	mov    %rax,0x140(%rbx)
  4136dc:	cmpw   $0x2,0x9a(%rbx)
  4136e4:	je     4137b5 <TIFFWriteCheck+0x1f7>
  4136ea:	mov    0x140(%rbx),%rax
  4136f1:	lea    0x0(,%rax,8),%rdi
  4136f9:	mov    $0x0,%eax
  4136fe:	callq  401270 <malloc@plt>
  413703:	mov    %rax,0x148(%rbx)
  41370a:	mov    0x140(%rbx),%rax
  413711:	lea    0x0(,%rax,8),%rdi
  413719:	mov    $0x0,%eax
  41371e:	callq  401270 <malloc@plt>
  413723:	mov    %rax,0x150(%rbx)
  41372a:	mov    0x148(%rbx),%rdi
  413731:	test   %rdi,%rdi
  413734:	je     4137c9 <TIFFWriteCheck+0x20b>
  41373a:	test   %rax,%rax
  41373d:	je     4137c9 <TIFFWriteCheck+0x20b>
  413743:	mov    0x140(%rbx),%rax
  41374a:	lea    0x0(,%rax,8),%rsi
  413752:	mov    $0x0,%eax
  413757:	callq  4012f0 <bzero@plt>
  41375c:	mov    0x140(%rbx),%rax
  413763:	lea    0x0(,%rax,8),%rsi
  41376b:	mov    0x150(%rbx),%rdi
  413772:	mov    $0x0,%eax
  413777:	callq  4012f0 <bzero@plt>
  41377c:	orq    $0xc000000,0x20(%rbx)
  413784:	jmpq   41364e <TIFFWriteCheck+0x90>
  413789:	mov    $0x1,%eax
  41378e:	mov    $0xffffffff,%edx
  413793:	cmp    %rdx,0x50(%rdi)
  413797:	je     4137a0 <TIFFWriteCheck+0x1e2>
  413799:	cmpq   $0x0,0x38(%rdi)
  41379e:	jne    4137ac <TIFFWriteCheck+0x1ee>
  4137a0:	mov    %rax,0x138(%rbx)
  4137a7:	jmpq   4136ce <TIFFWriteCheck+0x110>
  4137ac:	callq  413326 <TIFFNumberOfTiles>
  4137b1:	mov    %eax,%eax
  4137b3:	jmp    4137a0 <TIFFWriteCheck+0x1e2>
  4137b5:	movzwl 0x70(%rbx),%edx
  4137b9:	imul   %rdx,%rax
  4137bd:	mov    %rax,0x140(%rbx)
  4137c4:	jmpq   4136ea <TIFFWriteCheck+0x12c>
  4137c9:	movq   $0x0,0x140(%rbx)
  4137d4:	movzwl 0xe(%rbx),%eax
  4137d8:	and    $0x80,%ax
  4137dc:	mov    $0x41aa79,%ecx
  4137e1:	mov    $0x41aa7e,%eax
  4137e6:	cmove  %rax,%rcx
  4137ea:	mov    (%rbx),%rdx
  4137ed:	mov    $0x41aaa2,%esi
  4137f2:	mov    %rbp,%rdi
  4137f5:	mov    $0x0,%eax
  4137fa:	callq  412a93 <TIFFError>
  4137ff:	mov    $0x0,%eax
  413804:	jmpq   413608 <TIFFWriteCheck+0x4a>

0000000000413809 <TIFFBufferSetup>:
  413809:	push   %r12
  41380b:	push   %rbp
  41380c:	push   %rbx
  41380d:	mov    %rdi,%rbp
  413810:	mov    %rsi,%r12
  413813:	testb  $0x80,0xe(%rdi)
  413817:	je     413875 <TIFFBufferSetup+0x6c>
  413819:	callq  413493 <TIFFTileSize>
  41381e:	mov    %eax,%edx
  413820:	cltq   
  413822:	mov    %rax,0x220(%rbp)
  413829:	cmp    $0x2000,%edx
  41382f:	mov    $0x2000,%ebx
  413834:	cmovge %edx,%ebx
  413837:	mov    %ebx,%edi
  413839:	mov    $0x0,%eax
  41383e:	callq  401270 <malloc@plt>
  413843:	mov    %rax,0x298(%rbp)
  41384a:	test   %rax,%rax
  41384d:	je     413884 <TIFFBufferSetup+0x7b>
  41384f:	movslq %ebx,%rdx
  413852:	mov    %rdx,0x2a0(%rbp)
  413859:	movq   $0x0,0x2b0(%rbp)
  413864:	mov    %rax,0x2a8(%rbp)
  41386b:	mov    $0x1,%eax
  413870:	pop    %rbx
  413871:	pop    %rbp
  413872:	pop    %r12
  413874:	retq   
  413875:	callq  412fcd <TIFFScanlineSize>
  41387a:	mov    %eax,%edx
  41387c:	mov    %eax,0x290(%rbp)
  413882:	jmp    413829 <TIFFBufferSetup+0x20>
  413884:	mov    0x0(%rbp),%rdx
  413888:	mov    $0x41a908,%esi
  41388d:	mov    %r12,%rdi
  413890:	callq  412a93 <TIFFError>
  413895:	mov    $0x0,%eax
  41389a:	jmp    413870 <TIFFBufferSetup+0x67>

000000000041389c <TIFFAppendToStrip>:
  41389c:	push   %r14
  41389e:	push   %r13
  4138a0:	push   %r12
  4138a2:	push   %rbp
  4138a3:	push   %rbx
  4138a4:	mov    %rdi,%rbx
  4138a7:	mov    %rdx,%r14
  4138aa:	mov    %ecx,%r12d
  4138ad:	mov    %esi,%ebp
  4138af:	lea    0x0(,%rbp,8),%r13
  4138b7:	mov    0x148(%rdi),%rax
  4138be:	mov    (%rax,%rbp,8),%rsi
  4138c2:	test   %rsi,%rsi
  4138c5:	je     413916 <TIFFAppendToStrip+0x7a>
  4138c7:	cmpq   $0x0,0x208(%rdi)
  4138cf:	jne    41394b <TIFFAppendToStrip+0xaf>
  4138d1:	movswl 0x8(%rdi),%edi
  4138d5:	mov    $0x0,%edx
  4138da:	mov    $0x0,%eax
  4138df:	callq  401190 <lseek@plt>
  4138e4:	mov    0x148(%rbx),%rdx
  4138eb:	cmp    (%rdx,%rbp,8),%rax
  4138ef:	je     413939 <TIFFAppendToStrip+0x9d>
  4138f1:	mov    0x1f8(%rbx),%rcx
  4138f8:	mov    (%rbx),%rdx
  4138fb:	mov    $0x41aabd,%esi
  413900:	mov    $0x61fc50,%edi
  413905:	mov    $0x0,%eax
  41390a:	callq  412a93 <TIFFError>
  41390f:	mov    $0x0,%eax
  413914:	jmp    41397e <TIFFAppendToStrip+0xe2>
  413916:	movswl 0x8(%rdi),%edi
  41391a:	mov    $0x2,%edx
  41391f:	mov    $0x0,%esi
  413924:	mov    $0x0,%eax
  413929:	callq  401190 <lseek@plt>
  41392e:	mov    0x148(%rbx),%rdx
  413935:	mov    %rax,(%rdx,%rbp,8)
  413939:	mov    0x148(%rbx),%rax
  413940:	mov    (%rax,%rbp,8),%rax
  413944:	mov    %rax,0x208(%rbx)
  41394b:	movswl 0x8(%rbx),%edi
  41394f:	mov    %r12d,%edx
  413952:	mov    %r14,%rsi
  413955:	mov    $0x0,%eax
  41395a:	callq  401120 <write@plt>
  41395f:	cmp    %r12d,%eax
  413962:	jne    413987 <TIFFAppendToStrip+0xeb>
  413964:	mov    %r12d,%r12d
  413967:	add    %r12,0x208(%rbx)
  41396e:	add    0x150(%rbx),%r13
  413975:	add    %r12,0x0(%r13)
  413979:	mov    $0x1,%eax
  41397e:	pop    %rbx
  41397f:	pop    %rbp
  413980:	pop    %r12
  413982:	pop    %r13
  413984:	pop    %r14
  413986:	retq   
  413987:	mov    0x1f8(%rbx),%rcx
  41398e:	mov    (%rbx),%rdx
  413991:	mov    $0x41a928,%esi
  413996:	mov    $0x61fc50,%edi
  41399b:	mov    $0x0,%eax
  4139a0:	callq  412a93 <TIFFError>
  4139a5:	mov    $0x0,%eax
  4139aa:	jmp    41397e <TIFFAppendToStrip+0xe2>

00000000004139ac <TIFFWriteScanline>:
  4139ac:	push   %r15
  4139ae:	push   %r14
  4139b0:	push   %r13
  4139b2:	push   %r12
  4139b4:	push   %rbp
  4139b5:	push   %rbx
  4139b6:	sub    $0x8,%rsp
  4139ba:	mov    %rdi,%rbx
  4139bd:	mov    %rsi,%r14
  4139c0:	mov    %edx,%r12d
  4139c3:	mov    %ecx,%r13d
  4139c6:	mov    $0x61fc90,%edx
  4139cb:	mov    $0x0,%esi
  4139d0:	callq  4135be <TIFFWriteCheck>
  4139d5:	test   %eax,%eax
  4139d7:	je     413d26 <TIFFWriteScanline+0x37a>
  4139dd:	testb  $0x4,0xe(%rbx)
  4139e1:	je     413ae6 <TIFFWriteScanline+0x13a>
  4139e7:	mov    %r12d,%eax
  4139ea:	cmp    0x38(%rbx),%rax
  4139ee:	jb     413b1e <TIFFWriteScanline+0x172>
  4139f4:	cmpw   $0x2,0x9a(%rbx)
  4139fc:	je     413b05 <TIFFWriteScanline+0x159>
  413a02:	lea    0x1(%r12),%edx
  413a07:	mov    %edx,%ecx
  413a09:	mov    %rcx,0x38(%rbx)
  413a0d:	mov    $0x1,%r15d
  413a13:	mov    $0x0,%edx
  413a18:	divq   0x78(%rbx)
  413a1c:	mov    %rax,%rbp
  413a1f:	cmp    %ebp,0x204(%rbx)
  413a25:	je     413a8f <TIFFWriteScanline+0xe3>
  413a27:	cmpq   $0x0,0x2b0(%rbx)
  413a2f:	jg     413b7e <TIFFWriteScanline+0x1d2>
  413a35:	mov    %ebp,0x204(%rbx)
  413a3b:	movslq %ebp,%rcx
  413a3e:	cmp    0x138(%rbx),%rcx
  413a45:	jb     413a50 <TIFFWriteScanline+0xa4>
  413a47:	test   %r15d,%r15d
  413a4a:	jne    413b98 <TIFFWriteScanline+0x1ec>
  413a50:	mov    %rcx,%rax
  413a53:	mov    $0x0,%edx
  413a58:	divq   0x138(%rbx)
  413a5f:	imul   0x78(%rbx),%rdx
  413a64:	mov    %rdx,0x1f8(%rbx)
  413a6b:	mov    0x230(%rbx),%rdx
  413a72:	test   %rdx,%rdx
  413a75:	je     413a89 <TIFFWriteScanline+0xdd>
  413a77:	mov    %rbx,%rdi
  413a7a:	mov    $0x0,%eax
  413a7f:	callq  *%rdx
  413a81:	test   %eax,%eax
  413a83:	je     413d3a <TIFFWriteScanline+0x38e>
  413a89:	orw    $0x200,0xe(%rbx)
  413a8f:	movslq %ebp,%rbp
  413a92:	mov    0x140(%rbx),%rax
  413a99:	cmp    %rax,%rbp
  413a9c:	jae    413bb9 <TIFFWriteScanline+0x20d>
  413aa2:	mov    %r12d,%r12d
  413aa5:	mov    0x1f8(%rbx),%rax
  413aac:	cmp    %rax,%r12
  413aaf:	jne    413cac <TIFFWriteScanline+0x300>
  413ab5:	mov    0x290(%rbx),%edx
  413abb:	mov    %r13d,%ecx
  413abe:	mov    %r14,%rsi
  413ac1:	mov    %rbx,%rdi
  413ac4:	mov    $0x0,%eax
  413ac9:	callq  *0x248(%rbx)
  413acf:	addq   $0x1,0x1f8(%rbx)
  413ad7:	add    $0x8,%rsp
  413adb:	pop    %rbx
  413adc:	pop    %rbp
  413add:	pop    %r12
  413adf:	pop    %r13
  413ae1:	pop    %r14
  413ae3:	pop    %r15
  413ae5:	retq   
  413ae6:	mov    $0x61fc90,%esi
  413aeb:	mov    %rbx,%rdi
  413aee:	callq  413809 <TIFFBufferSetup>
  413af3:	test   %eax,%eax
  413af5:	je     413d30 <TIFFWriteScanline+0x384>
  413afb:	orw    $0x4,0xe(%rbx)
  413b00:	jmpq   4139e7 <TIFFWriteScanline+0x3b>
  413b05:	mov    $0x41a948,%esi
  413b0a:	mov    (%rbx),%rdi
  413b0d:	mov    $0x0,%eax
  413b12:	callq  412a93 <TIFFError>
  413b17:	mov    $0xffffffff,%eax
  413b1c:	jmp    413ad7 <TIFFWriteScanline+0x12b>
  413b1e:	cmpw   $0x2,0x9a(%rbx)
  413b26:	jne    413b73 <TIFFWriteScanline+0x1c7>
  413b28:	movzwl 0x70(%rbx),%edx
  413b2c:	movzwl %dx,%ecx
  413b2f:	cmp    %r13d,%ecx
  413b32:	jbe    413b54 <TIFFWriteScanline+0x1a8>
  413b34:	mov    %r13d,%ebp
  413b37:	imul   0x138(%rbx),%ebp
  413b3e:	mov    $0x0,%edx
  413b43:	divq   0x78(%rbx)
  413b47:	add    %eax,%ebp
  413b49:	mov    $0x0,%r15d
  413b4f:	jmpq   413a1f <TIFFWriteScanline+0x73>
  413b54:	mov    %r13d,%edx
  413b57:	mov    $0x41a980,%esi
  413b5c:	mov    (%rbx),%rdi
  413b5f:	mov    $0x0,%eax
  413b64:	callq  412a93 <TIFFError>
  413b69:	mov    $0xffffffff,%eax
  413b6e:	jmpq   413ad7 <TIFFWriteScanline+0x12b>
  413b73:	mov    $0x0,%r15d
  413b79:	jmpq   413a13 <TIFFWriteScanline+0x67>
  413b7e:	mov    %rbx,%rdi
  413b81:	callq  412b2b <TIFFFlushData>
  413b86:	test   %eax,%eax
  413b88:	jne    413a35 <TIFFWriteScanline+0x89>
  413b8e:	mov    $0xffffffff,%eax
  413b93:	jmpq   413ad7 <TIFFWriteScanline+0x12b>
  413b98:	mov    0x78(%rbx),%rsi
  413b9c:	mov    %esi,%eax
  413b9e:	add    0x38(%rbx),%eax
  413ba1:	sub    $0x1,%eax
  413ba4:	mov    $0x0,%edx
  413ba9:	div    %esi
  413bab:	mov    %eax,%eax
  413bad:	mov    %rax,0x138(%rbx)
  413bb4:	jmpq   413a50 <TIFFWriteScanline+0xa4>
  413bb9:	cmpw   $0x1,0x9a(%rbx)
  413bc1:	jne    413c67 <TIFFWriteScanline+0x2bb>
  413bc7:	lea    0x8(,%rax,8),%rsi
  413bcf:	mov    0x148(%rbx),%rdi
  413bd6:	mov    $0x0,%eax
  413bdb:	callq  4012b0 <realloc@plt>
  413be0:	mov    %rax,0x148(%rbx)
  413be7:	mov    0x140(%rbx),%rax
  413bee:	lea    0x8(,%rax,8),%rsi
  413bf6:	mov    0x150(%rbx),%rdi
  413bfd:	mov    $0x0,%eax
  413c02:	callq  4012b0 <realloc@plt>
  413c07:	mov    %rax,0x150(%rbx)
  413c0e:	mov    0x148(%rbx),%rdx
  413c15:	test   %rax,%rax
  413c18:	je     413c80 <TIFFWriteScanline+0x2d4>
  413c1a:	test   %rdx,%rdx
  413c1d:	je     413c80 <TIFFWriteScanline+0x2d4>
  413c1f:	mov    0x140(%rbx),%rax
  413c26:	lea    (%rdx,%rax,8),%rdi
  413c2a:	mov    $0x8,%esi
  413c2f:	mov    $0x0,%eax
  413c34:	callq  4012f0 <bzero@plt>
  413c39:	mov    0x140(%rbx),%rdx
  413c40:	mov    0x150(%rbx),%rax
  413c47:	lea    (%rax,%rdx,8),%rdi
  413c4b:	mov    $0x8,%esi
  413c50:	mov    $0x0,%eax
  413c55:	callq  4012f0 <bzero@plt>
  413c5a:	addq   $0x1,0x140(%rbx)
  413c62:	jmpq   413aa2 <TIFFWriteScanline+0xf6>
  413c67:	mov    $0x41aae8,%ecx
  413c6c:	mov    $0x1fb,%edx
  413c71:	mov    $0x41aadb,%esi
  413c76:	mov    $0x41a9a0,%edi
  413c7b:	callq  4011b0 <__assert_fail@plt>
  413c80:	movq   $0x0,0x140(%rbx)
  413c8b:	mov    (%rbx),%rdx
  413c8e:	mov    $0x41a9d0,%esi
  413c93:	mov    $0x61fc90,%edi
  413c98:	mov    $0x0,%eax
  413c9d:	callq  412a93 <TIFFError>
  413ca2:	mov    $0xffffffff,%eax
  413ca7:	jmpq   413ad7 <TIFFWriteScanline+0x12b>
  413cac:	mov    0x278(%rbx),%rcx
  413cb3:	test   %rcx,%rcx
  413cb6:	je     413d0a <TIFFWriteScanline+0x35e>
  413cb8:	cmp    %rax,%r12
  413cbb:	jge    413ce6 <TIFFWriteScanline+0x33a>
  413cbd:	mov    %rbp,%rax
  413cc0:	mov    $0x0,%edx
  413cc5:	divq   0x138(%rbx)
  413ccc:	imul   0x78(%rbx),%rdx
  413cd1:	mov    %rdx,0x1f8(%rbx)
  413cd8:	mov    0x298(%rbx),%rax
  413cdf:	mov    %rax,0x2a8(%rbx)
  413ce6:	mov    %r12,%rsi
  413ce9:	sub    0x1f8(%rbx),%rsi
  413cf0:	mov    %rbx,%rdi
  413cf3:	mov    $0x0,%eax
  413cf8:	callq  *%rcx
  413cfa:	test   %eax,%eax
  413cfc:	je     413d44 <TIFFWriteScanline+0x398>
  413cfe:	mov    %r12,0x1f8(%rbx)
  413d05:	jmpq   413ab5 <TIFFWriteScanline+0x109>
  413d0a:	mov    $0x41a9f8,%esi
  413d0f:	mov    (%rbx),%rdi
  413d12:	mov    $0x0,%eax
  413d17:	callq  412a93 <TIFFError>
  413d1c:	mov    $0xffffffff,%eax
  413d21:	jmpq   413ad7 <TIFFWriteScanline+0x12b>
  413d26:	mov    $0xffffffff,%eax
  413d2b:	jmpq   413ad7 <TIFFWriteScanline+0x12b>
  413d30:	mov    $0xffffffff,%eax
  413d35:	jmpq   413ad7 <TIFFWriteScanline+0x12b>
  413d3a:	mov    $0xffffffff,%eax
  413d3f:	jmpq   413ad7 <TIFFWriteScanline+0x12b>
  413d44:	mov    $0xffffffff,%eax
  413d49:	jmpq   413ad7 <TIFFWriteScanline+0x12b>

0000000000413d4e <TIFFWriteEncodedStrip>:
  413d4e:	push   %r14
  413d50:	push   %r13
  413d52:	push   %r12
  413d54:	push   %rbp
  413d55:	push   %rbx
  413d56:	mov    %rdi,%rbx
  413d59:	mov    %esi,%r12d
  413d5c:	mov    %rdx,%r14
  413d5f:	mov    %ecx,%r13d
  413d62:	mov    $0x61fc70,%edx
  413d67:	mov    $0x0,%esi
  413d6c:	callq  4135be <TIFFWriteCheck>
  413d71:	test   %eax,%eax
  413d73:	je     413ec0 <TIFFWriteEncodedStrip+0x172>
  413d79:	mov    %r12d,%ebp
  413d7c:	mov    0x140(%rbx),%r8
  413d83:	cmp    %r8,%rbp
  413d86:	jae    413e4c <TIFFWriteEncodedStrip+0xfe>
  413d8c:	testb  $0x4,0xe(%rbx)
  413d90:	je     413e6d <TIFFWriteEncodedStrip+0x11f>
  413d96:	mov    %r12d,0x204(%rbx)
  413d9d:	andw   $0xfdff,0xe(%rbx)
  413da3:	mov    0x230(%rbx),%rdx
  413daa:	test   %rdx,%rdx
  413dad:	je     413dc1 <TIFFWriteEncodedStrip+0x73>
  413daf:	mov    %rbx,%rdi
  413db2:	mov    $0x0,%eax
  413db7:	callq  *%rdx
  413db9:	test   %eax,%eax
  413dbb:	je     413ed4 <TIFFWriteEncodedStrip+0x186>
  413dc1:	mov    %rbp,%rax
  413dc4:	mov    $0x0,%edx
  413dc9:	divq   0x138(%rbx)
  413dd0:	mov    %rax,%rcx
  413dd3:	mov    %r13d,%edx
  413dd6:	mov    %r14,%rsi
  413dd9:	mov    %rbx,%rdi
  413ddc:	mov    $0x0,%eax
  413de1:	callq  *0x258(%rbx)
  413de7:	test   %eax,%eax
  413de9:	je     413e43 <TIFFWriteEncodedStrip+0xf5>
  413deb:	mov    0x238(%rbx),%rdx
  413df2:	test   %rdx,%rdx
  413df5:	je     413e09 <TIFFWriteEncodedStrip+0xbb>
  413df7:	mov    %rbx,%rdi
  413dfa:	mov    $0x0,%eax
  413dff:	callq  *%rdx
  413e01:	test   %eax,%eax
  413e03:	je     413ede <TIFFWriteEncodedStrip+0x190>
  413e09:	movzwl 0x6c(%rbx),%edx
  413e0d:	movsbl 0xc(%rbx),%eax
  413e11:	cmp    %eax,%edx
  413e13:	je     413e1b <TIFFWriteEncodedStrip+0xcd>
  413e15:	testb  $0x20,0xe(%rbx)
  413e19:	je     413e88 <TIFFWriteEncodedStrip+0x13a>
  413e1b:	mov    0x2b0(%rbx),%rcx
  413e22:	test   %rcx,%rcx
  413e25:	jg     413e9f <TIFFWriteEncodedStrip+0x151>
  413e27:	movq   $0x0,0x2b0(%rbx)
  413e32:	mov    0x298(%rbx),%rax
  413e39:	mov    %rax,0x2a8(%rbx)
  413e40:	mov    %r13d,%eax
  413e43:	pop    %rbx
  413e44:	pop    %rbp
  413e45:	pop    %r12
  413e47:	pop    %r13
  413e49:	pop    %r14
  413e4b:	retq   
  413e4c:	mov    %r12d,%ecx
  413e4f:	mov    (%rbx),%rdx
  413e52:	mov    $0x41aa30,%esi
  413e57:	mov    $0x61fc70,%edi
  413e5c:	mov    $0x0,%eax
  413e61:	callq  412a93 <TIFFError>
  413e66:	mov    $0xffffffff,%eax
  413e6b:	jmp    413e43 <TIFFWriteEncodedStrip+0xf5>
  413e6d:	mov    $0x61fc70,%esi
  413e72:	mov    %rbx,%rdi
  413e75:	callq  413809 <TIFFBufferSetup>
  413e7a:	test   %eax,%eax
  413e7c:	je     413eca <TIFFWriteEncodedStrip+0x17c>
  413e7e:	orw    $0x4,0xe(%rbx)
  413e83:	jmpq   413d96 <TIFFWriteEncodedStrip+0x48>
  413e88:	mov    0x298(%rbx),%rdi
  413e8f:	mov    0x2b0(%rbx),%esi
  413e95:	callq  4130a4 <TIFFReverseBits>
  413e9a:	jmpq   413e1b <TIFFWriteEncodedStrip+0xcd>
  413e9f:	mov    0x298(%rbx),%rdx
  413ea6:	mov    %r12d,%esi
  413ea9:	mov    %rbx,%rdi
  413eac:	callq  41389c <TIFFAppendToStrip>
  413eb1:	test   %eax,%eax
  413eb3:	jne    413e27 <TIFFWriteEncodedStrip+0xd9>
  413eb9:	mov    $0xffffffff,%eax
  413ebe:	jmp    413e43 <TIFFWriteEncodedStrip+0xf5>
  413ec0:	mov    $0xffffffff,%eax
  413ec5:	jmpq   413e43 <TIFFWriteEncodedStrip+0xf5>
  413eca:	mov    $0xffffffff,%eax
  413ecf:	jmpq   413e43 <TIFFWriteEncodedStrip+0xf5>
  413ed4:	mov    $0xffffffff,%eax
  413ed9:	jmpq   413e43 <TIFFWriteEncodedStrip+0xf5>
  413ede:	mov    $0xffffffff,%eax
  413ee3:	jmpq   413e43 <TIFFWriteEncodedStrip+0xf5>

0000000000413ee8 <TIFFWriteRawStrip>:
  413ee8:	push   %r13
  413eea:	push   %r12
  413eec:	push   %rbp
  413eed:	push   %rbx
  413eee:	sub    $0x8,%rsp
  413ef2:	mov    %rdi,%rbp
  413ef5:	mov    %esi,%r12d
  413ef8:	mov    %rdx,%r13
  413efb:	mov    %ecx,%ebx
  413efd:	mov    $0x61fc30,%edx
  413f02:	mov    $0x0,%esi
  413f07:	callq  4135be <TIFFWriteCheck>
  413f0c:	test   %eax,%eax
  413f0e:	je     413f66 <TIFFWriteRawStrip+0x7e>
  413f10:	mov    0x140(%rbp),%r8
  413f17:	mov    %r12d,%eax
  413f1a:	cmp    %r8,%rax
  413f1d:	jae    413f44 <TIFFWriteRawStrip+0x5c>
  413f1f:	mov    %ebx,%ecx
  413f21:	mov    %r13,%rdx
  413f24:	mov    %r12d,%esi
  413f27:	mov    %rbp,%rdi
  413f2a:	callq  41389c <TIFFAppendToStrip>
  413f2f:	test   %eax,%eax
  413f31:	mov    $0xffffffff,%eax
  413f36:	cmovne %ebx,%eax
  413f39:	add    $0x8,%rsp
  413f3d:	pop    %rbx
  413f3e:	pop    %rbp
  413f3f:	pop    %r12
  413f41:	pop    %r13
  413f43:	retq   
  413f44:	mov    %r12d,%ecx
  413f47:	mov    0x0(%rbp),%rdx
  413f4b:	mov    $0x41aa30,%esi
  413f50:	mov    $0x61fc30,%edi
  413f55:	mov    $0x0,%eax
  413f5a:	callq  412a93 <TIFFError>
  413f5f:	mov    $0xffffffff,%eax
  413f64:	jmp    413f39 <TIFFWriteRawStrip+0x51>
  413f66:	mov    $0xffffffff,%eax
  413f6b:	jmp    413f39 <TIFFWriteRawStrip+0x51>

0000000000413f6d <TIFFWriteEncodedTile>:
  413f6d:	push   %r14
  413f6f:	push   %r13
  413f71:	push   %r12
  413f73:	push   %rbp
  413f74:	push   %rbx
  413f75:	mov    %rdi,%rbx
  413f78:	mov    %esi,%ebp
  413f7a:	mov    %rdx,%r14
  413f7d:	mov    %ecx,%r13d
  413f80:	mov    $0x61fc10,%edx
  413f85:	mov    $0x1,%esi
  413f8a:	callq  4135be <TIFFWriteCheck>
  413f8f:	test   %eax,%eax
  413f91:	je     41413f <TIFFWriteEncodedTile+0x1d2>
  413f97:	mov    %ebp,%r12d
  413f9a:	mov    0x140(%rbx),%r8
  413fa1:	cmp    %r8,%r12
  413fa4:	jae    4140d0 <TIFFWriteEncodedTile+0x163>
  413faa:	testb  $0x4,0xe(%rbx)
  413fae:	je     4140f0 <TIFFWriteEncodedTile+0x183>
  413fb4:	mov    %ebp,0x218(%rbx)
  413fba:	mov    0x50(%rbx),%rsi
  413fbe:	mov    %esi,%eax
  413fc0:	add    0x38(%rbx),%eax
  413fc3:	sub    $0x1,%eax
  413fc6:	mov    $0x0,%edx
  413fcb:	div    %esi
  413fcd:	mov    %eax,%ecx
  413fcf:	mov    %ebp,%eax
  413fd1:	mov    $0x0,%edx
  413fd6:	div    %ecx
  413fd8:	mov    %edx,%edx
  413fda:	imul   %rsi,%rdx
  413fde:	mov    %rdx,0x1f8(%rbx)
  413fe5:	mov    0x48(%rbx),%rcx
  413fe9:	mov    %ecx,%eax
  413feb:	add    0x30(%rbx),%eax
  413fee:	sub    $0x1,%eax
  413ff1:	mov    $0x0,%edx
  413ff6:	div    %ecx
  413ff8:	mov    %eax,%esi
  413ffa:	mov    %ebp,%eax
  413ffc:	mov    $0x0,%edx
  414001:	div    %esi
  414003:	mov    %edx,%edx
  414005:	imul   %rcx,%rdx
  414009:	mov    %rdx,0x210(%rbx)
  414010:	andw   $0xfdff,0xe(%rbx)
  414016:	mov    0x230(%rbx),%rdx
  41401d:	test   %rdx,%rdx
  414020:	je     414034 <TIFFWriteEncodedTile+0xc7>
  414022:	mov    %rbx,%rdi
  414025:	mov    $0x0,%eax
  41402a:	callq  *%rdx
  41402c:	test   %eax,%eax
  41402e:	je     414150 <TIFFWriteEncodedTile+0x1e3>
  414034:	mov    0x220(%rbx),%rax
  41403b:	mov    %r13d,%edx
  41403e:	cmp    %rax,%rdx
  414041:	cmovg  %eax,%r13d
  414045:	mov    %r12,%rax
  414048:	mov    $0x0,%edx
  41404d:	divq   0x138(%rbx)
  414054:	mov    %rax,%rcx
  414057:	mov    %r13d,%edx
  41405a:	mov    %r14,%rsi
  41405d:	mov    %rbx,%rdi
  414060:	mov    $0x0,%eax
  414065:	callq  *0x268(%rbx)
  41406b:	test   %eax,%eax
  41406d:	je     4140c7 <TIFFWriteEncodedTile+0x15a>
  41406f:	mov    0x238(%rbx),%rdx
  414076:	test   %rdx,%rdx
  414079:	je     41408d <TIFFWriteEncodedTile+0x120>
  41407b:	mov    %rbx,%rdi
  41407e:	mov    $0x0,%eax
  414083:	callq  *%rdx
  414085:	test   %eax,%eax
  414087:	je     41415a <TIFFWriteEncodedTile+0x1ed>
  41408d:	movzwl 0x6c(%rbx),%edx
  414091:	movsbl 0xc(%rbx),%eax
  414095:	cmp    %eax,%edx
  414097:	je     41409f <TIFFWriteEncodedTile+0x132>
  414099:	testb  $0x20,0xe(%rbx)
  41409d:	je     41410b <TIFFWriteEncodedTile+0x19e>
  41409f:	mov    0x2b0(%rbx),%rcx
  4140a6:	test   %rcx,%rcx
  4140a9:	jg     41411f <TIFFWriteEncodedTile+0x1b2>
  4140ab:	movq   $0x0,0x2b0(%rbx)
  4140b6:	mov    0x298(%rbx),%rax
  4140bd:	mov    %rax,0x2a8(%rbx)
  4140c4:	mov    %r13d,%eax
  4140c7:	pop    %rbx
  4140c8:	pop    %rbp
  4140c9:	pop    %r12
  4140cb:	pop    %r13
  4140cd:	pop    %r14
  4140cf:	retq   
  4140d0:	mov    %ebp,%ecx
  4140d2:	mov    (%rbx),%rdx
  4140d5:	mov    $0x41aa58,%esi
  4140da:	mov    $0x61fc10,%edi
  4140df:	mov    $0x0,%eax
  4140e4:	callq  412a93 <TIFFError>
  4140e9:	mov    $0xffffffff,%eax
  4140ee:	jmp    4140c7 <TIFFWriteEncodedTile+0x15a>
  4140f0:	mov    $0x61fc10,%esi
  4140f5:	mov    %rbx,%rdi
  4140f8:	callq  413809 <TIFFBufferSetup>
  4140fd:	test   %eax,%eax
  4140ff:	je     414146 <TIFFWriteEncodedTile+0x1d9>
  414101:	orw    $0x4,0xe(%rbx)
  414106:	jmpq   413fb4 <TIFFWriteEncodedTile+0x47>
  41410b:	mov    0x298(%rbx),%rdi
  414112:	mov    0x2b0(%rbx),%esi
  414118:	callq  4130a4 <TIFFReverseBits>
  41411d:	jmp    41409f <TIFFWriteEncodedTile+0x132>
  41411f:	mov    0x298(%rbx),%rdx
  414126:	mov    %ebp,%esi
  414128:	mov    %rbx,%rdi
  41412b:	callq  41389c <TIFFAppendToStrip>
  414130:	test   %eax,%eax
  414132:	jne    4140ab <TIFFWriteEncodedTile+0x13e>
  414138:	mov    $0xffffffff,%eax
  41413d:	jmp    4140c7 <TIFFWriteEncodedTile+0x15a>
  41413f:	mov    $0xffffffff,%eax
  414144:	jmp    4140c7 <TIFFWriteEncodedTile+0x15a>
  414146:	mov    $0xffffffff,%eax
  41414b:	jmpq   4140c7 <TIFFWriteEncodedTile+0x15a>
  414150:	mov    $0xffffffff,%eax
  414155:	jmpq   4140c7 <TIFFWriteEncodedTile+0x15a>
  41415a:	mov    $0xffffffff,%eax
  41415f:	jmpq   4140c7 <TIFFWriteEncodedTile+0x15a>

0000000000414164 <TIFFWriteTile>:
  414164:	push   %r15
  414166:	push   %r14
  414168:	push   %r13
  41416a:	push   %r12
  41416c:	push   %rbp
  41416d:	push   %rbx
  41416e:	sub    $0x8,%rsp
  414172:	mov    %rdi,%rbx
  414175:	mov    %rsi,%r15
  414178:	mov    %rdx,%rbp
  41417b:	mov    %rcx,%r12
  41417e:	mov    %r8,%r13
  414181:	mov    %r9d,%r14d
  414184:	mov    %r9d,%r8d
  414187:	mov    %r13,%rcx
  41418a:	mov    %r12,%rdx
  41418d:	mov    %rbp,%rsi
  414190:	callq  413277 <TIFFCheckTile>
  414195:	test   %eax,%eax
  414197:	je     4141ce <TIFFWriteTile+0x6a>
  414199:	mov    %r14d,%r8d
  41419c:	mov    %r13d,%ecx
  41419f:	mov    %r12,%rdx
  4141a2:	mov    %rbp,%rsi
  4141a5:	mov    %rbx,%rdi
  4141a8:	callq  41315a <TIFFComputeTile>
  4141ad:	mov    $0xffffffff,%ecx
  4141b2:	mov    %r15,%rdx
  4141b5:	mov    %eax,%esi
  4141b7:	mov    %rbx,%rdi
  4141ba:	callq  413f6d <TIFFWriteEncodedTile>
  4141bf:	add    $0x8,%rsp
  4141c3:	pop    %rbx
  4141c4:	pop    %rbp
  4141c5:	pop    %r12
  4141c7:	pop    %r13
  4141c9:	pop    %r14
  4141cb:	pop    %r15
  4141cd:	retq   
  4141ce:	mov    $0xffffffff,%eax
  4141d3:	jmp    4141bf <TIFFWriteTile+0x5b>

00000000004141d5 <TIFFWriteRawTile>:
  4141d5:	push   %r13
  4141d7:	push   %r12
  4141d9:	push   %rbp
  4141da:	push   %rbx
  4141db:	sub    $0x8,%rsp
  4141df:	mov    %rdi,%rbp
  4141e2:	mov    %esi,%r12d
  4141e5:	mov    %rdx,%r13
  4141e8:	mov    %ecx,%ebx
  4141ea:	mov    $0x61fbf0,%edx
  4141ef:	mov    $0x1,%esi
  4141f4:	callq  4135be <TIFFWriteCheck>
  4141f9:	test   %eax,%eax
  4141fb:	je     414253 <TIFFWriteRawTile+0x7e>
  4141fd:	mov    0x140(%rbp),%r8
  414204:	mov    %r12d,%eax
  414207:	cmp    %r8,%rax
  41420a:	jae    414231 <TIFFWriteRawTile+0x5c>
  41420c:	mov    %ebx,%ecx
  41420e:	mov    %r13,%rdx
  414211:	mov    %r12d,%esi
  414214:	mov    %rbp,%rdi
  414217:	callq  41389c <TIFFAppendToStrip>
  41421c:	test   %eax,%eax
  41421e:	mov    $0xffffffff,%eax
  414223:	cmovne %ebx,%eax
  414226:	add    $0x8,%rsp
  41422a:	pop    %rbx
  41422b:	pop    %rbp
  41422c:	pop    %r12
  41422e:	pop    %r13
  414230:	retq   
  414231:	mov    %r12d,%ecx
  414234:	mov    0x0(%rbp),%rdx
  414238:	mov    $0x41aa58,%esi
  41423d:	mov    $0x61fbf0,%edi
  414242:	mov    $0x0,%eax
  414247:	callq  412a93 <TIFFError>
  41424c:	mov    $0xffffffff,%eax
  414251:	jmp    414226 <TIFFWriteRawTile+0x51>
  414253:	mov    $0xffffffff,%eax
  414258:	jmp    414226 <TIFFWriteRawTile+0x51>

000000000041425a <TIFFFlushData1>:
  41425a:	mov    0x2b0(%rdi),%rsi
  414261:	mov    $0x1,%eax
  414266:	test   %rsi,%rsi
  414269:	jle    4142dd <TIFFFlushData1+0x83>
  41426b:	push   %rbx
  41426c:	mov    %rdi,%rbx
  41426f:	movzwl 0x6c(%rdi),%edx
  414273:	movsbl 0xc(%rdi),%eax
  414277:	cmp    %eax,%edx
  414279:	je     414281 <TIFFFlushData1+0x27>
  41427b:	testb  $0x20,0xe(%rdi)
  41427f:	je     4142c7 <TIFFFlushData1+0x6d>
  414281:	mov    0x2b0(%rbx),%rcx
  414288:	mov    0x298(%rbx),%rdx
  41428f:	testb  $0x80,0xe(%rbx)
  414293:	je     4142d5 <TIFFFlushData1+0x7b>
  414295:	mov    0x218(%rbx),%esi
  41429b:	mov    %rbx,%rdi
  41429e:	callq  41389c <TIFFAppendToStrip>
  4142a3:	test   %eax,%eax
  4142a5:	je     4142c5 <TIFFFlushData1+0x6b>
  4142a7:	movq   $0x0,0x2b0(%rbx)
  4142b2:	mov    0x298(%rbx),%rax
  4142b9:	mov    %rax,0x2a8(%rbx)
  4142c0:	mov    $0x1,%eax
  4142c5:	pop    %rbx
  4142c6:	retq   
  4142c7:	mov    0x298(%rdi),%rdi
  4142ce:	callq  4130a4 <TIFFReverseBits>
  4142d3:	jmp    414281 <TIFFFlushData1+0x27>
  4142d5:	mov    0x204(%rbx),%esi
  4142db:	jmp    41429b <TIFFFlushData1+0x41>
  4142dd:	repz retq 

00000000004142df <TIFFNoEncode>:
  4142df:	sub    $0x8,%rsp
  4142e3:	mov    %rsi,%rcx
  4142e6:	movzwl 0x66(%rdi),%edx
  4142ea:	cmp    0x20b9d8(%rip),%edx        # 61fcc8 <CompressionSchemes+0x8>
  4142f0:	je     41432c <TIFFNoEncode+0x4d>
  4142f2:	mov    $0x61fcd8,%eax
  4142f7:	cmp    0x8(%rax),%edx
  4142fa:	je     41430d <TIFFNoEncode+0x2e>
  4142fc:	add    $0x18,%rax
  414300:	cmp    $0x61fdb0,%rax
  414306:	jb     4142f7 <TIFFNoEncode+0x18>
  414308:	mov    $0x0,%eax
  41430d:	mov    (%rax),%rdx
  414310:	mov    $0x41aaf8,%esi
  414315:	mov    (%rdi),%rdi
  414318:	mov    $0x0,%eax
  41431d:	callq  412a93 <TIFFError>
  414322:	mov    $0xffffffff,%eax
  414327:	add    $0x8,%rsp
  41432b:	retq   
  41432c:	mov    $0x61fcc0,%eax
  414331:	jmp    41430d <TIFFNoEncode+0x2e>

0000000000414333 <TIFFNoRowEncode>:
  414333:	sub    $0x8,%rsp
  414337:	mov    $0x41ab75,%esi
  41433c:	mov    $0x0,%eax
  414341:	callq  4142df <TIFFNoEncode>
  414346:	add    $0x8,%rsp
  41434a:	retq   

000000000041434b <TIFFNoStripEncode>:
  41434b:	sub    $0x8,%rsp
  41434f:	mov    $0x41aa7e,%esi
  414354:	mov    $0x0,%eax
  414359:	callq  4142df <TIFFNoEncode>
  41435e:	add    $0x8,%rsp
  414362:	retq   

0000000000414363 <TIFFNoTileEncode>:
  414363:	sub    $0x8,%rsp
  414367:	mov    $0x41aa79,%esi
  41436c:	mov    $0x0,%eax
  414371:	callq  4142df <TIFFNoEncode>
  414376:	add    $0x8,%rsp
  41437a:	retq   

000000000041437b <TIFFNoDecode>:
  41437b:	sub    $0x8,%rsp
  41437f:	mov    %rsi,%rcx
  414382:	movzwl 0x66(%rdi),%edx
  414386:	cmp    0x20b93c(%rip),%edx        # 61fcc8 <CompressionSchemes+0x8>
  41438c:	je     4143c8 <TIFFNoDecode+0x4d>
  41438e:	mov    $0x61fcd8,%eax
  414393:	cmp    0x8(%rax),%edx
  414396:	je     4143a9 <TIFFNoDecode+0x2e>
  414398:	add    $0x18,%rax
  41439c:	cmp    $0x61fdb0,%rax
  4143a2:	jb     414393 <TIFFNoDecode+0x18>
  4143a4:	mov    $0x0,%eax
  4143a9:	mov    (%rax),%rdx
  4143ac:	mov    $0x41ab20,%esi
  4143b1:	mov    (%rdi),%rdi
  4143b4:	mov    $0x0,%eax
  4143b9:	callq  412a93 <TIFFError>
  4143be:	mov    $0xffffffff,%eax
  4143c3:	add    $0x8,%rsp
  4143c7:	retq   
  4143c8:	mov    $0x61fcc0,%eax
  4143cd:	jmp    4143a9 <TIFFNoDecode+0x2e>

00000000004143cf <TIFFNoRowDecode>:
  4143cf:	sub    $0x8,%rsp
  4143d3:	mov    $0x41ab75,%esi
  4143d8:	mov    $0x0,%eax
  4143dd:	callq  41437b <TIFFNoDecode>
  4143e2:	add    $0x8,%rsp
  4143e6:	retq   

00000000004143e7 <TIFFNoStripDecode>:
  4143e7:	sub    $0x8,%rsp
  4143eb:	mov    $0x41aa7e,%esi
  4143f0:	mov    $0x0,%eax
  4143f5:	callq  41437b <TIFFNoDecode>
  4143fa:	add    $0x8,%rsp
  4143fe:	retq   

00000000004143ff <TIFFNoTileDecode>:
  4143ff:	sub    $0x8,%rsp
  414403:	mov    $0x41aa79,%esi
  414408:	mov    $0x0,%eax
  41440d:	callq  41437b <TIFFNoDecode>
  414412:	add    $0x8,%rsp
  414416:	retq   

0000000000414417 <TIFFSetCompressionScheme>:
  414417:	sub    $0x8,%rsp
  41441b:	cmp    0x20b8a7(%rip),%esi        # 61fcc8 <CompressionSchemes+0x8>
  414421:	je     4144fd <TIFFSetCompressionScheme+0xe6>
  414427:	mov    $0x61fcd8,%ecx
  41442c:	cmp    0x8(%rcx),%esi
  41442f:	je     41445e <TIFFSetCompressionScheme+0x47>
  414431:	add    $0x18,%rcx
  414435:	cmp    $0x61fdb0,%rcx
  41443c:	jb     41442c <TIFFSetCompressionScheme+0x15>
  41443e:	mov    %esi,%ecx
  414440:	mov    %esi,%edx
  414442:	mov    $0x41ab48,%esi
  414447:	mov    (%rdi),%rdi
  41444a:	mov    $0x0,%eax
  41444f:	callq  412a93 <TIFFError>
  414454:	mov    $0x0,%eax
  414459:	jmpq   4144f8 <TIFFSetCompressionScheme+0xe1>
  41445e:	test   %rcx,%rcx
  414461:	je     41443e <TIFFSetCompressionScheme+0x27>
  414463:	movq   $0x0,0x228(%rdi)
  41446e:	movq   $0x4143cf,0x240(%rdi)
  414479:	movq   $0x4143e7,0x250(%rdi)
  414484:	movq   $0x4143ff,0x260(%rdi)
  41448f:	movq   $0x0,0x230(%rdi)
  41449a:	movq   $0x0,0x238(%rdi)
  4144a5:	movq   $0x414333,0x248(%rdi)
  4144b0:	movq   $0x41434b,0x258(%rdi)
  4144bb:	movq   $0x414363,0x268(%rdi)
  4144c6:	movq   $0x0,0x270(%rdi)
  4144d1:	movq   $0x0,0x278(%rdi)
  4144dc:	movq   $0x0,0x280(%rdi)
  4144e7:	andw   $0xffdf,0xe(%rdi)
  4144ec:	movb   $0x0,0xd(%rdi)
  4144f0:	mov    $0x0,%eax
  4144f5:	callq  *0x10(%rcx)
  4144f8:	add    $0x8,%rsp
  4144fc:	retq   
  4144fd:	mov    $0x61fcc0,%ecx
  414502:	jmpq   414463 <TIFFSetCompressionScheme+0x4c>

0000000000414507 <TIFFSetupShortLong>:
  414507:	mov    %si,(%rdx)
  41450a:	movq   $0x1,0x8(%rdx)
  414512:	cmp    $0xffff,%rcx
  414519:	ja     41453d <TIFFSetupShortLong+0x36>
  41451b:	movw   $0x3,0x2(%rdx)
  414521:	cmpw   $0x4d4d,0x1d8(%rdi)
  41452a:	je     414549 <TIFFSetupShortLong+0x42>
  41452c:	mov    0x1f0(%rdi),%rax
  414533:	and    0x18(%rax),%rcx
  414537:	mov    %rcx,0x10(%rdx)
  41453b:	repz retq 
  41453d:	movw   $0x4,0x2(%rdx)
  414543:	mov    %rcx,0x10(%rdx)
  414547:	jmp    41453b <TIFFSetupShortLong+0x34>
  414549:	mov    0x1f0(%rdi),%rax
  414550:	and    0x18(%rax),%rcx
  414554:	mov    %rcx,%rax
  414557:	mov    0x1e8(%rdi),%rcx
  41455e:	mov    0xc(%rcx),%ecx
  414561:	shl    %cl,%rax
  414564:	mov    %rax,%rcx
  414567:	jmp    414537 <TIFFSetupShortLong+0x30>

0000000000414569 <TIFFWriteData>:
  414569:	push   %r14
  41456b:	push   %r13
  41456d:	push   %r12
  41456f:	push   %rbp
  414570:	push   %rbx
  414571:	mov    %rdi,%rbp
  414574:	mov    %rsi,%rbx
  414577:	mov    %rdx,%r13
  41457a:	mov    0x22dc77(%rip),%rsi        # 6421f8 <dataoff>
  414581:	mov    %rsi,0x10(%rbx)
  414585:	mov    0x8(%rbx),%r12
  414589:	movzwl 0x2(%rbx),%eax
  41458d:	mov    0x61f1e0(,%rax,4),%r14d
  414595:	movswl 0x8(%rdi),%edi
  414599:	mov    $0x0,%edx
  41459e:	mov    $0x0,%eax
  4145a3:	callq  401190 <lseek@plt>
  4145a8:	cmp    0x10(%rbx),%rax
  4145ac:	je     4145db <TIFFWriteData+0x72>
  4145ae:	movzwl (%rbx),%edi
  4145b1:	callq  410ebe <TIFFFieldWithTag>
  4145b6:	mov    0x10(%rax),%rdx
  4145ba:	mov    $0x41abd8,%esi
  4145bf:	mov    0x0(%rbp),%rdi
  4145c3:	mov    $0x0,%eax
  4145c8:	callq  412a93 <TIFFError>
  4145cd:	mov    $0x0,%eax
  4145d2:	pop    %rbx
  4145d3:	pop    %rbp
  4145d4:	pop    %r12
  4145d6:	pop    %r13
  4145d8:	pop    %r14
  4145da:	retq   
  4145db:	imul   %r14d,%r12d
  4145df:	movswl 0x8(%rbp),%edi
  4145e3:	mov    %r12d,%edx
  4145e6:	mov    %r13,%rsi
  4145e9:	mov    $0x0,%eax
  4145ee:	callq  401120 <write@plt>
  4145f3:	cmp    %r12d,%eax
  4145f6:	jne    4145ae <TIFFWriteData+0x45>
  4145f8:	add    $0x1,%r12d
  4145fc:	and    $0xfffffffe,%r12d
  414600:	movslq %r12d,%r12
  414603:	add    %r12,0x22dbee(%rip)        # 6421f8 <dataoff>
  41460a:	mov    $0x1,%eax
  41460f:	jmp    4145d2 <TIFFWriteData+0x69>

0000000000414611 <TIFFWriteShortArray>:
  414611:	mov    %dx,(%rcx)
  414614:	mov    %si,0x2(%rcx)
  414618:	movslq %r8d,%rax
  41461b:	mov    %rax,0x8(%rcx)
  41461f:	cmp    $0x2,%r8d
  414623:	jg     414684 <TIFFWriteShortArray+0x73>
  414625:	cmpw   $0x4d4d,0x1d8(%rdi)
  41462e:	je     414645 <TIFFWriteShortArray+0x34>
  414630:	movzwl (%r9),%edx
  414634:	mov    %rdx,0x10(%rcx)
  414638:	mov    $0x1,%eax
  41463d:	cmp    $0x2,%r8d
  414641:	je     41466e <TIFFWriteShortArray+0x5d>
  414643:	repz retq 
  414645:	movzwl (%r9),%edx
  414649:	shl    $0x10,%rdx
  41464d:	mov    %rdx,0x10(%rcx)
  414651:	mov    $0x1,%eax
  414656:	cmp    $0x2,%r8d
  41465a:	jne    414643 <TIFFWriteShortArray+0x32>
  41465c:	movzwl 0x2(%r9),%eax
  414661:	or     %rax,%rdx
  414664:	mov    %rdx,0x10(%rcx)
  414668:	mov    $0x1,%eax
  41466d:	retq   
  41466e:	movzwl 0x2(%r9),%eax
  414673:	shl    $0x10,%rax
  414677:	or     %rax,%rdx
  41467a:	mov    %rdx,0x10(%rcx)
  41467e:	mov    $0x1,%eax
  414683:	retq   
  414684:	sub    $0x8,%rsp
  414688:	mov    %r9,%rdx
  41468b:	mov    %rcx,%rsi
  41468e:	callq  414569 <TIFFWriteData>
  414693:	add    $0x8,%rsp
  414697:	retq   

0000000000414698 <TIFFWriteRationalArray>:
  414698:	push   %r14
  41469a:	push   %r13
  41469c:	push   %r12
  41469e:	push   %rbp
  41469f:	push   %rbx
  4146a0:	mov    %rdi,%r12
  4146a3:	mov    %rcx,%rbx
  4146a6:	mov    %r8d,%r13d
  4146a9:	mov    %r9,%r14
  4146ac:	mov    %dx,(%rcx)
  4146af:	mov    %si,0x2(%rcx)
  4146b3:	movslq %r8d,%rdi
  4146b6:	mov    %rdi,0x8(%rcx)
  4146ba:	shl    $0x4,%rdi
  4146be:	mov    $0x0,%eax
  4146c3:	callq  401270 <malloc@plt>
  4146c8:	mov    %rax,%rbp
  4146cb:	test   %r13d,%r13d
  4146ce:	jle    414757 <TIFFWriteRationalArray+0xbf>
  4146d4:	mov    %r14,%r9
  4146d7:	mov    %rax,%rdx
  4146da:	lea    -0x1(%r13),%eax
  4146de:	shl    $0x4,%rax
  4146e2:	lea    0x10(%rbp,%rax,1),%rsi
  4146e7:	movsd  0x68b9(%rip),%xmm3        # 41afa8 <__PRETTY_FUNCTION__.2297+0x4c0>
  4146ef:	movsd  0x4f61(%rip),%xmm2        # 419658 <__dso_handle+0x890>
  4146f7:	movsd  0x68b1(%rip),%xmm1        # 41afb0 <__PRETTY_FUNCTION__.2297+0x4c8>
  4146ff:	movapd %xmm1,%xmm4
  414703:	movabs $0x8000000000000000,%rdi
  41470d:	jmp    414733 <TIFFWriteRationalArray+0x9b>
  41470f:	subsd  %xmm4,%xmm0
  414713:	cvttsd2si %xmm0,%rax
  414718:	mov    %rax,(%rdx)
  41471b:	xor    %rdi,(%rdx)
  41471e:	movq   $0x2710,0x8(%rcx)
  414726:	add    $0x4,%r9
  41472a:	add    $0x10,%rdx
  41472e:	cmp    %rsi,%rdx
  414731:	je     414757 <TIFFWriteRationalArray+0xbf>
  414733:	mov    %rdx,%rcx
  414736:	pxor   %xmm0,%xmm0
  41473a:	cvtss2sd (%r9),%xmm0
  41473f:	mulsd  %xmm3,%xmm0
  414743:	addsd  %xmm2,%xmm0
  414747:	ucomisd %xmm1,%xmm0
  41474b:	jae    41470f <TIFFWriteRationalArray+0x77>
  41474d:	cvttsd2si %xmm0,%rax
  414752:	mov    %rax,(%rdx)
  414755:	jmp    41471e <TIFFWriteRationalArray+0x86>
  414757:	mov    %rbp,%rdx
  41475a:	mov    %rbx,%rsi
  41475d:	mov    %r12,%rdi
  414760:	callq  414569 <TIFFWriteData>
  414765:	mov    %eax,%ebx
  414767:	mov    %rbp,%rdi
  41476a:	callq  4010b0 <free@plt>
  41476f:	mov    %ebx,%eax
  414771:	pop    %rbx
  414772:	pop    %rbp
  414773:	pop    %r12
  414775:	pop    %r13
  414777:	pop    %r14
  414779:	retq   

000000000041477a <TIFFWriteRational>:
  41477a:	push   %rbp
  41477b:	push   %rbx
  41477c:	sub    $0x28,%rsp
  414780:	mov    %rdi,%rbp
  414783:	mov    %rcx,%rbx
  414786:	movss  %xmm0,0xc(%rsp)
  41478c:	mov    %dx,(%rcx)
  41478f:	mov    %si,0x2(%rcx)
  414793:	movq   $0x1,0x8(%rcx)
  41479b:	cmp    $0x5,%esi
  41479e:	je     4147ee <TIFFWriteRational+0x74>
  4147a0:	pxor   %xmm0,%xmm0
  4147a4:	cvtss2sd 0xc(%rsp),%xmm0
  4147aa:	mulsd  0x67f6(%rip),%xmm0        # 41afa8 <__PRETTY_FUNCTION__.2297+0x4c0>
  4147b2:	addsd  0x4e9e(%rip),%xmm0        # 419658 <__dso_handle+0x890>
  4147ba:	ucomisd 0x67ee(%rip),%xmm0        # 41afb0 <__PRETTY_FUNCTION__.2297+0x4c8>
  4147c2:	jae    414827 <TIFFWriteRational+0xad>
  4147c4:	cvttsd2si %xmm0,%rax
  4147c9:	mov    %rax,0x10(%rsp)
  4147ce:	movq   $0x2710,0x18(%rsp)
  4147d7:	lea    0x10(%rsp),%rdx
  4147dc:	mov    %rbx,%rsi
  4147df:	mov    %rbp,%rdi
  4147e2:	callq  414569 <TIFFWriteData>
  4147e7:	add    $0x28,%rsp
  4147eb:	pop    %rbx
  4147ec:	pop    %rbp
  4147ed:	retq   
  4147ee:	pxor   %xmm0,%xmm0
  4147f2:	ucomiss 0xc(%rsp),%xmm0
  4147f7:	jbe    4147a0 <TIFFWriteRational+0x26>
  4147f9:	movzwl %dx,%edi
  4147fc:	callq  410ebe <TIFFFieldWithTag>
  414801:	pxor   %xmm0,%xmm0
  414805:	cvtss2sd 0xc(%rsp),%xmm0
  41480b:	mov    0x10(%rax),%rdx
  41480f:	mov    $0x41ac00,%esi
  414814:	mov    0x0(%rbp),%rdi
  414818:	mov    $0x1,%eax
  41481d:	callq  413526 <TIFFWarning>
  414822:	jmpq   4147a0 <TIFFWriteRational+0x26>
  414827:	subsd  0x6781(%rip),%xmm0        # 41afb0 <__PRETTY_FUNCTION__.2297+0x4c8>
  41482f:	cvttsd2si %xmm0,%rax
  414834:	mov    %rax,0x10(%rsp)
  414839:	movabs $0x8000000000000000,%rax
  414843:	xor    %rax,0x10(%rsp)
  414848:	jmp    4147ce <TIFFWriteRational+0x54>

000000000041484a <TIFFWriteJPEGCTables>:
  41484a:	push   %r14
  41484c:	push   %r13
  41484e:	push   %r12
  414850:	push   %rbp
  414851:	push   %rbx
  414852:	sub    $0x40,%rsp
  414856:	mov    %rdi,%rbp
  414859:	mov    %esi,%r14d
  41485c:	mov    %rdx,%r13
  41485f:	mov    %rcx,%r12
  414862:	mov    %si,0x20(%rsp)
  414867:	movw   $0x1,0x22(%rsp)
  41486e:	movzwl 0x70(%rdi),%edx
  414872:	movzwl %dx,%eax
  414875:	mov    $0x1,%ebx
  41487a:	test   %eax,%eax
  41487c:	jle    4148d4 <TIFFWriteJPEGCTables+0x8a>
  41487e:	mov    -0x8(%r12,%rbx,8),%rdx
  414883:	mov    %rdx,%rax
  414886:	lea    0x10(%rdx),%rdi
  41488a:	mov    $0x0,%ecx
  41488f:	movzbl (%rax),%esi
  414892:	add    %esi,%ecx
  414894:	add    $0x1,%rax
  414898:	cmp    %rax,%rdi
  41489b:	jne    41488f <TIFFWriteJPEGCTables+0x45>
  41489d:	add    $0x10,%ecx
  4148a0:	movslq %ecx,%rcx
  4148a3:	mov    %rcx,0x28(%rsp)
  4148a8:	lea    0x20(%rsp),%rsi
  4148ad:	mov    %rbp,%rdi
  4148b0:	callq  414569 <TIFFWriteData>
  4148b5:	test   %eax,%eax
  4148b7:	je     4148fa <TIFFWriteJPEGCTables+0xb0>
  4148b9:	mov    0x30(%rsp),%rax
  4148be:	mov    %rax,-0x8(%rsp,%rbx,8)
  4148c3:	mov    %ebx,%ecx
  4148c5:	movzwl 0x70(%rbp),%edx
  4148c9:	movzwl %dx,%eax
  4148cc:	add    $0x1,%rbx
  4148d0:	cmp    %ecx,%eax
  4148d2:	jg     41487e <TIFFWriteJPEGCTables+0x34>
  4148d4:	mov    %r14w,0x0(%r13)
  4148d9:	movw   $0x4,0x2(%r13)
  4148e0:	movzwl %dx,%edx
  4148e3:	mov    %rdx,0x8(%r13)
  4148e7:	cmp    $0x1,%eax
  4148ea:	je     414907 <TIFFWriteJPEGCTables+0xbd>
  4148ec:	mov    %rsp,%rdx
  4148ef:	mov    %r13,%rsi
  4148f2:	mov    %rbp,%rdi
  4148f5:	callq  414569 <TIFFWriteData>
  4148fa:	add    $0x40,%rsp
  4148fe:	pop    %rbx
  4148ff:	pop    %rbp
  414900:	pop    %r12
  414902:	pop    %r13
  414904:	pop    %r14
  414906:	retq   
  414907:	mov    (%rsp),%rdx
  41490b:	mov    %rdx,0x10(%r13)
  41490f:	jmp    4148fa <TIFFWriteJPEGCTables+0xb0>

0000000000414911 <TIFFWriteDirectory>:
  414911:	push   %r15
  414913:	push   %r14
  414915:	push   %r13
  414917:	push   %r12
  414919:	push   %rbp
  41491a:	push   %rbx
  41491b:	sub    $0x88,%rsp
  414922:	mov    $0x1,%ebp
  414927:	cmpw   $0x0,0xa(%rdi)
  41492c:	je     4156b2 <TIFFWriteDirectory+0xda1>
  414932:	mov    %rdi,%rbx
  414935:	movzwl 0xe(%rdi),%eax
  414939:	test   $0x2,%ah
  41493c:	je     41495e <TIFFWriteDirectory+0x4d>
  41493e:	and    $0xfd,%ah
  414941:	mov    %ax,0xe(%rdi)
  414945:	mov    0x238(%rdi),%rdx
  41494c:	test   %rdx,%rdx
  41494f:	je     41495e <TIFFWriteDirectory+0x4d>
  414951:	mov    $0x0,%eax
  414956:	callq  *%rdx
  414958:	mov    %eax,%ebp
  41495a:	test   %eax,%eax
  41495c:	je     4149d8 <TIFFWriteDirectory+0xc7>
  41495e:	mov    0x270(%rbx),%rdx
  414965:	test   %rdx,%rdx
  414968:	je     414974 <TIFFWriteDirectory+0x63>
  41496a:	mov    %rbx,%rdi
  41496d:	mov    $0x0,%eax
  414972:	callq  *%rdx
  414974:	mov    0x280(%rbx),%rdx
  41497b:	test   %rdx,%rdx
  41497e:	je     41498a <TIFFWriteDirectory+0x79>
  414980:	mov    %rbx,%rdi
  414983:	mov    $0x0,%eax
  414988:	callq  *%rdx
  41498a:	cmpq   $0x0,0x2b0(%rbx)
  414992:	jg     4149ef <TIFFWriteDirectory+0xde>
  414994:	testb  $0x40,0xe(%rbx)
  414998:	je     4149c1 <TIFFWriteDirectory+0xb0>
  41499a:	mov    0x298(%rbx),%rdi
  4149a1:	test   %rdi,%rdi
  4149a4:	je     4149c1 <TIFFWriteDirectory+0xb0>
  4149a6:	callq  4010b0 <free@plt>
  4149ab:	movq   $0x0,0x298(%rbx)
  4149b6:	movq   $0x0,0x2b0(%rbx)
  4149c1:	andw   $0xfff3,0xe(%rbx)
  4149c6:	mov    $0x0,%ecx
  4149cb:	mov    $0x0,%r13d
  4149d1:	mov    $0x1,%esi
  4149d6:	jmp    414a23 <TIFFWriteDirectory+0x112>
  4149d8:	mov    $0x41ac48,%esi
  4149dd:	mov    (%rbx),%rdi
  4149e0:	mov    $0x0,%eax
  4149e5:	callq  412a93 <TIFFError>
  4149ea:	jmpq   4156b2 <TIFFWriteDirectory+0xda1>
  4149ef:	mov    %rbx,%rdi
  4149f2:	mov    $0x0,%eax
  4149f7:	callq  41425a <TIFFFlushData1>
  4149fc:	mov    %eax,%ebp
  4149fe:	test   %eax,%eax
  414a00:	jne    414994 <TIFFWriteDirectory+0x83>
  414a02:	mov    $0x41ac78,%esi
  414a07:	mov    (%rbx),%rdi
  414a0a:	mov    $0x0,%eax
  414a0f:	callq  412a93 <TIFFError>
  414a14:	jmpq   4156b2 <TIFFWriteDirectory+0xda1>
  414a19:	add    $0x1,%rcx
  414a1d:	cmp    $0x3c,%rcx
  414a21:	je     414a3e <TIFFWriteDirectory+0x12d>
  414a23:	mov    %rcx,%rdx
  414a26:	shr    $0x5,%rdx
  414a2a:	mov    %esi,%eax
  414a2c:	shl    %cl,%eax
  414a2e:	test   %eax,0x20(%rbx,%rdx,8)
  414a32:	je     414a19 <TIFFWriteDirectory+0x108>
  414a34:	cmp    $0x5,%rcx
  414a38:	adc    $0x1,%r13d
  414a3c:	jmp    414a19 <TIFFWriteDirectory+0x108>
  414a3e:	lea    0x0(%r13,%r13,2),%ebp
  414a43:	shl    $0x3,%ebp
  414a46:	mov    %ebp,0x18(%rsp)
  414a4a:	mov    %ebp,%edi
  414a4c:	mov    $0x0,%eax
  414a51:	callq  401270 <malloc@plt>
  414a56:	mov    %rax,0x8(%rsp)
  414a5b:	test   %rax,%rax
  414a5e:	je     414b14 <TIFFWriteDirectory+0x203>
  414a64:	cmpq   $0x0,0x10(%rbx)
  414a69:	je     414b2b <TIFFWriteDirectory+0x21a>
  414a6f:	mov    0x10(%rbx),%rdx
  414a73:	movslq %ebp,%rax
  414a76:	lea    0xa(%rdx,%rax,1),%rax
  414a7b:	lea    0x1(%rax),%rdx
  414a7f:	test   $0x1,%al
  414a81:	cmovne %rdx,%rax
  414a85:	mov    %rax,%rsi
  414a88:	mov    %rax,0x22d769(%rip)        # 6421f8 <dataoff>
  414a8f:	movswl 0x8(%rbx),%edi
  414a93:	mov    $0x0,%edx
  414a98:	mov    $0x0,%eax
  414a9d:	callq  401190 <lseek@plt>
  414aa2:	addl   $0x1,0x200(%rbx)
  414aa9:	lea    0x20(%rbx),%rax
  414aad:	mov    %rax,(%rsp)
  414ab1:	mov    $0x10,%edx
  414ab6:	lea    0x60(%rsp),%rsi
  414abb:	mov    %rax,%rdi
  414abe:	mov    $0x0,%eax
  414ac3:	callq  4012d0 <bcopy@plt>
  414ac8:	mov    0x68(%rsp),%rax
  414acd:	test   $0x4,%al
  414acf:	je     414aee <TIFFWriteDirectory+0x1dd>
  414ad1:	cmpw   $0x0,0xbc(%rbx)
  414ad9:	jne    414aee <TIFFWriteDirectory+0x1dd>
  414adb:	and    $0xfffffffb,%eax
  414ade:	mov    %rax,0x68(%rsp)
  414ae3:	sub    $0x1,%r13d
  414ae7:	lea    -0x18(%rbp),%eax
  414aea:	mov    %eax,0x18(%rsp)
  414aee:	movzwl 0x20a72a(%rip),%r14d        # 61f220 <tiffFieldInfo>
  414af6:	test   %r14w,%r14w
  414afa:	je     415657 <TIFFWriteDirectory+0xd46>
  414b00:	mov    0x8(%rsp),%r12
  414b05:	mov    $0x61f220,%ebp
  414b0a:	mov    %r13d,0x1c(%rsp)
  414b0f:	jmpq   414ea7 <TIFFWriteDirectory+0x596>
  414b14:	mov    $0x41aca8,%esi
  414b19:	mov    (%rbx),%rdi
  414b1c:	callq  412a93 <TIFFError>
  414b21:	mov    $0x0,%ebp
  414b26:	jmpq   4156b2 <TIFFWriteDirectory+0xda1>
  414b2b:	movswl 0x8(%rbx),%edi
  414b2f:	mov    $0x2,%edx
  414b34:	mov    $0x0,%esi
  414b39:	mov    $0x0,%eax
  414b3e:	callq  401190 <lseek@plt>
  414b43:	add    $0x1,%rax
  414b47:	and    $0xfffffffffffffffe,%rax
  414b4b:	mov    %rax,0x10(%rbx)
  414b4f:	mov    0x1e0(%rbx),%rdx
  414b56:	test   %rdx,%rdx
  414b59:	je     414b65 <TIFFWriteDirectory+0x254>
  414b5b:	mov    %rdx,0x40(%rsp)
  414b60:	jmpq   414c02 <TIFFWriteDirectory+0x2f1>
  414b65:	mov    %rax,0x1e0(%rbx)
  414b6c:	movswl 0x8(%rbx),%edi
  414b70:	mov    $0x0,%esi
  414b75:	mov    $0x0,%eax
  414b7a:	callq  401190 <lseek@plt>
  414b7f:	lea    0x1d8(%rbx),%rsi
  414b86:	movswl 0x8(%rbx),%edi
  414b8a:	mov    $0x10,%edx
  414b8f:	mov    $0x0,%eax
  414b94:	callq  401120 <write@plt>
  414b99:	cmp    $0x10,%eax
  414b9c:	je     414a6f <TIFFWriteDirectory+0x15e>
  414ba2:	mov    $0x41a4ba,%esi
  414ba7:	mov    (%rbx),%rdi
  414baa:	mov    $0x0,%eax
  414baf:	callq  412a93 <TIFFError>
  414bb4:	jmp    414bca <TIFFWriteDirectory+0x2b9>
  414bb6:	mov    $0x41acd0,%esi
  414bbb:	mov    $0x61fdb0,%edi
  414bc0:	mov    $0x0,%eax
  414bc5:	callq  412a93 <TIFFError>
  414bca:	mov    $0x0,%ebp
  414bcf:	jmpq   4156b2 <TIFFWriteDirectory+0xda1>
  414bd4:	lea    0x20(%rsp),%rdi
  414bd9:	callq  413028 <TIFFSwabShort>
  414bde:	jmp    414c48 <TIFFWriteDirectory+0x337>
  414be0:	mov    $0x41ad11,%esi
  414be5:	mov    $0x61fdb0,%edi
  414bea:	mov    $0x0,%eax
  414bef:	callq  412a93 <TIFFError>
  414bf4:	jmp    414bca <TIFFWriteDirectory+0x2b9>
  414bf6:	cmpq   $0x0,0x40(%rsp)
  414bfc:	je     414ca2 <TIFFWriteDirectory+0x391>
  414c02:	movswl 0x8(%rbx),%edi
  414c06:	mov    $0x0,%edx
  414c0b:	mov    0x40(%rsp),%rsi
  414c10:	mov    $0x0,%eax
  414c15:	callq  401190 <lseek@plt>
  414c1a:	cmp    0x40(%rsp),%rax
  414c1f:	jne    414bb6 <TIFFWriteDirectory+0x2a5>
  414c21:	movswl 0x8(%rbx),%edi
  414c25:	mov    $0x2,%edx
  414c2a:	lea    0x20(%rsp),%rsi
  414c2f:	mov    $0x0,%eax
  414c34:	callq  401200 <read@plt>
  414c39:	cmp    $0x2,%eax
  414c3c:	jne    414bb6 <TIFFWriteDirectory+0x2a5>
  414c42:	testb  $0x10,0xe(%rbx)
  414c46:	jne    414bd4 <TIFFWriteDirectory+0x2c3>
  414c48:	movzwl 0x20(%rsp),%eax
  414c4d:	lea    (%rax,%rax,2),%rsi
  414c51:	shl    $0x3,%rsi
  414c55:	movswl 0x8(%rbx),%edi
  414c59:	mov    $0x1,%edx
  414c5e:	mov    $0x0,%eax
  414c63:	callq  401190 <lseek@plt>
  414c68:	movswl 0x8(%rbx),%edi
  414c6c:	mov    $0x8,%edx
  414c71:	lea    0x40(%rsp),%rsi
  414c76:	mov    $0x0,%eax
  414c7b:	callq  401200 <read@plt>
  414c80:	cmp    $0x8,%eax
  414c83:	jne    414be0 <TIFFWriteDirectory+0x2cf>
  414c89:	testb  $0x10,0xe(%rbx)
  414c8d:	je     414bf6 <TIFFWriteDirectory+0x2e5>
  414c93:	lea    0x40(%rsp),%rdi
  414c98:	callq  413035 <TIFFSwabLong>
  414c9d:	jmpq   414bf6 <TIFFWriteDirectory+0x2e5>
  414ca2:	movswl 0x8(%rbx),%edi
  414ca6:	mov    $0x1,%edx
  414cab:	mov    $0xfffffffffffffff8,%rsi
  414cb2:	mov    $0x0,%eax
  414cb7:	callq  401190 <lseek@plt>
  414cbc:	lea    0x10(%rbx),%rsi
  414cc0:	movswl 0x8(%rbx),%edi
  414cc4:	mov    $0x8,%edx
  414cc9:	mov    $0x0,%eax
  414cce:	callq  401120 <write@plt>
  414cd3:	cmp    $0x8,%eax
  414cd6:	je     414a6f <TIFFWriteDirectory+0x15e>
  414cdc:	mov    $0x41ad2f,%esi
  414ce1:	mov    $0x61fdb0,%edi
  414ce6:	mov    $0x0,%eax
  414ceb:	callq  412a93 <TIFFError>
  414cf0:	jmpq   414bca <TIFFWriteDirectory+0x2b9>
  414cf5:	movzwl 0xe(%rbx),%eax
  414cf9:	and    $0x80,%ax
  414cfd:	cmp    $0x1,%ax
  414d01:	sbb    %eax,%eax
  414d03:	and    $0xffffffcd,%eax
  414d06:	add    $0x144,%ax
  414d0a:	movswl %ax,%edx
  414d0d:	movzwl %r14w,%r13d
  414d11:	cmp    %r13d,%edx
  414d14:	jne    414e94 <TIFFWriteDirectory+0x583>
  414d1a:	mov    0x148(%rbx),%rdx
  414d21:	mov    0x140(%rbx),%rcx
  414d28:	mov    %ax,(%r12)
  414d2d:	movw   $0x4,0x2(%r12)
  414d35:	movslq %ecx,%rax
  414d38:	mov    %rax,0x8(%r12)
  414d3d:	cmp    $0x1,%ecx
  414d40:	je     414d5a <TIFFWriteDirectory+0x449>
  414d42:	mov    %r12,%rsi
  414d45:	mov    %rbx,%rdi
  414d48:	callq  414569 <TIFFWriteData>
  414d4d:	test   %eax,%eax
  414d4f:	jne    414e73 <TIFFWriteDirectory+0x562>
  414d55:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  414d5a:	mov    (%rdx),%rax
  414d5d:	mov    %rax,0x10(%r12)
  414d62:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  414d67:	movzwl 0xe(%rbx),%eax
  414d6b:	and    $0x80,%ax
  414d6f:	cmp    $0x1,%ax
  414d73:	sbb    %eax,%eax
  414d75:	and    $0xffffffd2,%eax
  414d78:	add    $0x145,%ax
  414d7c:	movswl %ax,%edx
  414d7f:	movzwl %r14w,%r13d
  414d83:	cmp    %r13d,%edx
  414d86:	jne    414e94 <TIFFWriteDirectory+0x583>
  414d8c:	mov    0x150(%rbx),%rdx
  414d93:	mov    0x140(%rbx),%rcx
  414d9a:	mov    %ax,(%r12)
  414d9f:	movw   $0x4,0x2(%r12)
  414da7:	movslq %ecx,%rax
  414daa:	mov    %rax,0x8(%r12)
  414daf:	cmp    $0x1,%ecx
  414db2:	je     414dcc <TIFFWriteDirectory+0x4bb>
  414db4:	mov    %r12,%rsi
  414db7:	mov    %rbx,%rdi
  414dba:	callq  414569 <TIFFWriteData>
  414dbf:	test   %eax,%eax
  414dc1:	jne    414e73 <TIFFWriteDirectory+0x562>
  414dc7:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  414dcc:	mov    (%rdx),%rax
  414dcf:	mov    %rax,0x10(%r12)
  414dd4:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  414dd9:	movw   $0x140,(%r12)
  414de0:	movw   $0x3,0x2(%r12)
  414de8:	movzwl 0x62(%rbx),%ecx
  414dec:	mov    $0x1,%eax
  414df1:	shl    %cl,%rax
  414df4:	mov    %rax,0x8(%r12)
  414df9:	mov    0x22d3f8(%rip),%r15        # 6421f8 <dataoff>
  414e00:	lea    0xd0(%rbx),%r13
  414e07:	lea    0xe8(%rbx),%r14
  414e0e:	mov    0x0(%r13),%rdx
  414e12:	mov    %r12,%rsi
  414e15:	mov    %rbx,%rdi
  414e18:	callq  414569 <TIFFWriteData>
  414e1d:	test   %eax,%eax
  414e1f:	je     4156a3 <TIFFWriteDirectory+0xd92>
  414e25:	add    $0x8,%r13
  414e29:	cmp    %r13,%r14
  414e2c:	jne    414e0e <TIFFWriteDirectory+0x4fd>
  414e2e:	mov    0x8(%r12),%rax
  414e33:	lea    (%rax,%rax,2),%rax
  414e37:	mov    %rax,0x8(%r12)
  414e3c:	mov    %r15,0x10(%r12)
  414e41:	jmp    414e73 <TIFFWriteDirectory+0x562>
  414e43:	lea    0x18(%r12),%r13
  414e48:	mov    0x30(%rbx),%rcx
  414e4c:	mov    %r12,%rdx
  414e4f:	mov    $0x100,%esi
  414e54:	mov    %rbx,%rdi
  414e57:	callq  414507 <TIFFSetupShortLong>
  414e5c:	mov    0x38(%rbx),%rcx
  414e60:	mov    %r13,%rdx
  414e63:	mov    $0x101,%esi
  414e68:	mov    %rbx,%rdi
  414e6b:	callq  414507 <TIFFSetupShortLong>
  414e70:	mov    %r13,%r12
  414e73:	add    $0x18,%r12
  414e77:	movzwl 0xc(%rbp),%ecx
  414e7b:	mov    %ecx,%eax
  414e7d:	shr    $0x5,%ax
  414e81:	and    $0x7ff,%eax
  414e86:	mov    $0x1,%edx
  414e8b:	shl    %cl,%edx
  414e8d:	not    %edx
  414e8f:	and    %rdx,0x60(%rsp,%rax,8)
  414e94:	add    $0x18,%rbp
  414e98:	movzwl 0x0(%rbp),%r14d
  414e9d:	test   %r14w,%r14w
  414ea1:	je     415652 <TIFFWriteDirectory+0xd41>
  414ea7:	movzwl 0xc(%rbp),%ecx
  414eab:	cmp    $0xffff,%cx
  414eaf:	je     414e94 <TIFFWriteDirectory+0x583>
  414eb1:	mov    %ecx,%eax
  414eb3:	shr    $0x5,%ax
  414eb7:	and    $0x7ff,%eax
  414ebc:	mov    $0x1,%edx
  414ec1:	shl    %cl,%edx
  414ec3:	test   %edx,0x60(%rsp,%rax,8)
  414ec7:	je     414e94 <TIFFWriteDirectory+0x583>
  414ec9:	cmp    $0x3a,%cx
  414ecd:	ja     415297 <TIFFWriteDirectory+0x986>
  414ed3:	movzwl %cx,%ecx
  414ed6:	jmpq   *0x41ad70(,%rcx,8)
  414edd:	lea    0x18(%r12),%r13
  414ee2:	mov    0x48(%rbx),%rcx
  414ee6:	mov    %r12,%rdx
  414ee9:	mov    $0x142,%esi
  414eee:	mov    %rbx,%rdi
  414ef1:	callq  414507 <TIFFSetupShortLong>
  414ef6:	mov    0x50(%rbx),%rcx
  414efa:	mov    %r13,%rdx
  414efd:	mov    $0x143,%esi
  414f02:	mov    %rbx,%rdi
  414f05:	callq  414507 <TIFFSetupShortLong>
  414f0a:	mov    %r13,%r12
  414f0d:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  414f12:	movss  0x9c(%rbx),%xmm0
  414f1a:	mov    %r12,%rcx
  414f1d:	mov    $0x11e,%edx
  414f22:	mov    $0x5,%esi
  414f27:	mov    %rbx,%rdi
  414f2a:	callq  41477a <TIFFWriteRational>
  414f2f:	test   %eax,%eax
  414f31:	je     4156a3 <TIFFWriteDirectory+0xd92>
  414f37:	add    $0x18,%r12
  414f3b:	movss  0xa0(%rbx),%xmm0
  414f43:	mov    %r12,%rcx
  414f46:	mov    $0x11f,%edx
  414f4b:	mov    $0x5,%esi
  414f50:	mov    %rbx,%rdi
  414f53:	callq  41477a <TIFFWriteRational>
  414f58:	test   %eax,%eax
  414f5a:	jne    414e73 <TIFFWriteDirectory+0x562>
  414f60:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  414f65:	movss  0x90(%rbx),%xmm0
  414f6d:	mov    %r12,%rcx
  414f70:	mov    $0x11a,%edx
  414f75:	mov    $0x5,%esi
  414f7a:	mov    %rbx,%rdi
  414f7d:	callq  41477a <TIFFWriteRational>
  414f82:	test   %eax,%eax
  414f84:	je     4156a3 <TIFFWriteDirectory+0xd92>
  414f8a:	add    $0x18,%r12
  414f8e:	movss  0x94(%rbx),%xmm0
  414f96:	mov    %r12,%rcx
  414f99:	mov    $0x11b,%edx
  414f9e:	mov    $0x5,%esi
  414fa3:	mov    %rbx,%rdi
  414fa6:	callq  41477a <TIFFWriteRational>
  414fab:	test   %eax,%eax
  414fad:	jne    414e73 <TIFFWriteDirectory+0x562>
  414fb3:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  414fb8:	movzwl %r14w,%r13d
  414fbc:	movzwl 0x70(%rbx),%r14d
  414fc1:	movzwl %r14w,%r15d
  414fc5:	lea    0x20(%rsp),%rdx
  414fca:	mov    %r13d,%esi
  414fcd:	mov    (%rsp),%rdi
  414fd1:	mov    $0x0,%eax
  414fd6:	callq  4108cd <_TIFFgetfield>
  414fdb:	test   %r15d,%r15d
  414fde:	jle    414fff <TIFFWriteDirectory+0x6ee>
  414fe0:	movzwl 0x20(%rsp),%ecx
  414fe5:	lea    0x40(%rsp),%rax
  414fea:	lea    -0x1(%r15),%edx
  414fee:	lea    0x2(%rax,%rdx,2),%rdx
  414ff3:	mov    %cx,(%rax)
  414ff6:	add    $0x2,%rax
  414ffa:	cmp    %rax,%rdx
  414ffd:	jne    414ff3 <TIFFWriteDirectory+0x6e2>
  414fff:	lea    0x40(%rsp),%r9
  415004:	mov    %r15d,%r8d
  415007:	mov    %r12,%rcx
  41500a:	mov    %r13d,%edx
  41500d:	mov    $0x3,%esi
  415012:	mov    %rbx,%rdi
  415015:	callq  414611 <TIFFWriteShortArray>
  41501a:	test   %eax,%eax
  41501c:	jne    414e73 <TIFFWriteDirectory+0x562>
  415022:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  415027:	movzwl %r14w,%r14d
  41502b:	lea    0x40(%rsp),%rax
  415030:	lea    0x42(%rsp),%rcx
  415035:	mov    %rax,%rdx
  415038:	mov    %r14d,%esi
  41503b:	mov    (%rsp),%rdi
  41503f:	mov    $0x0,%eax
  415044:	callq  4108cd <_TIFFgetfield>
  415049:	lea    0x40(%rsp),%r9
  41504e:	mov    $0x2,%r8d
  415054:	mov    %r12,%rcx
  415057:	mov    %r14d,%edx
  41505a:	mov    $0x3,%esi
  41505f:	mov    %rbx,%rdi
  415062:	callq  414611 <TIFFWriteShortArray>
  415067:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  41506c:	movw   $0x207,0x20(%rsp)
  415073:	movw   $0x1,0x22(%rsp)
  41507a:	movq   $0x40,0x28(%rsp)
  415083:	movzwl 0x70(%rbx),%eax
  415087:	movzwl %ax,%edx
  41508a:	test   %edx,%edx
  41508c:	jle    4150d8 <TIFFWriteDirectory+0x7c7>
  41508e:	mov    $0x0,%r13d
  415094:	mov    $0x0,%r14d
  41509a:	mov    0x170(%rbx),%rax
  4150a1:	mov    (%rax,%r13,1),%rdx
  4150a5:	lea    0x20(%rsp),%rsi
  4150aa:	mov    %rbx,%rdi
  4150ad:	callq  414569 <TIFFWriteData>
  4150b2:	test   %eax,%eax
  4150b4:	je     4156a3 <TIFFWriteDirectory+0xd92>
  4150ba:	mov    0x30(%rsp),%rax
  4150bf:	mov    %rax,0x40(%rsp,%r13,1)
  4150c4:	add    $0x1,%r14d
  4150c8:	movzwl 0x70(%rbx),%eax
  4150cc:	movzwl %ax,%edx
  4150cf:	add    $0x8,%r13
  4150d3:	cmp    %edx,%r14d
  4150d6:	jl     41509a <TIFFWriteDirectory+0x789>
  4150d8:	movw   $0x207,(%r12)
  4150df:	movw   $0x4,0x2(%r12)
  4150e7:	movzwl %ax,%eax
  4150ea:	mov    %rax,0x8(%r12)
  4150ef:	cmp    $0x1,%edx
  4150f2:	je     415111 <TIFFWriteDirectory+0x800>
  4150f4:	lea    0x40(%rsp),%rdx
  4150f9:	mov    %r12,%rsi
  4150fc:	mov    %rbx,%rdi
  4150ff:	callq  414569 <TIFFWriteData>
  415104:	test   %eax,%eax
  415106:	jne    414e73 <TIFFWriteDirectory+0x562>
  41510c:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  415111:	mov    0x40(%rsp),%rax
  415116:	mov    %rax,0x10(%r12)
  41511b:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  415120:	mov    0x178(%rbx),%rcx
  415127:	mov    %r12,%rdx
  41512a:	mov    $0x208,%esi
  41512f:	mov    %rbx,%rdi
  415132:	callq  41484a <TIFFWriteJPEGCTables>
  415137:	test   %eax,%eax
  415139:	jne    414e73 <TIFFWriteDirectory+0x562>
  41513f:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  415144:	mov    0x180(%rbx),%rcx
  41514b:	mov    %r12,%rdx
  41514e:	mov    $0x209,%esi
  415153:	mov    %rbx,%rdi
  415156:	callq  41484a <TIFFWriteJPEGCTables>
  41515b:	test   %eax,%eax
  41515d:	jne    414e73 <TIFFWriteDirectory+0x562>
  415163:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  415168:	movzwl 0x70(%rbx),%r8d
  41516d:	mov    0x198(%rbx),%r9
  415174:	add    %r8d,%r8d
  415177:	mov    %r12,%rcx
  41517a:	mov    $0x214,%edx
  41517f:	mov    $0x5,%esi
  415184:	mov    %rbx,%rdi
  415187:	callq  414698 <TIFFWriteRationalArray>
  41518c:	test   %eax,%eax
  41518e:	jne    414e73 <TIFFWriteDirectory+0x562>
  415194:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  415199:	lea    0x1a0(%rbx),%r14
  4151a0:	movzwl 0x62(%rbx),%ecx
  4151a4:	mov    $0x2,%r15d
  4151aa:	shl    %cl,%r15
  4151ad:	cmpw   $0x1,0x70(%rbx)
  4151b2:	jbe    4151ea <TIFFWriteDirectory+0x8d9>
  4151b4:	mov    $0x1,%r13d
  4151ba:	movslq %r13d,%rax
  4151bd:	mov    (%r14,%rax,8),%rsi
  4151c1:	mov    0x1a0(%rbx),%rdi
  4151c8:	mov    %r15,%rdx
  4151cb:	mov    $0x0,%eax
  4151d0:	callq  4012a0 <bcmp@plt>
  4151d5:	test   %eax,%eax
  4151d7:	jne    41525f <TIFFWriteDirectory+0x94e>
  4151dd:	add    $0x1,%r13d
  4151e1:	movzwl 0x70(%rbx),%eax
  4151e5:	cmp    %eax,%r13d
  4151e8:	jl     4151ba <TIFFWriteDirectory+0x8a9>
  4151ea:	movw   $0x12d,(%r12)
  4151f1:	movw   $0x3,0x2(%r12)
  4151f9:	movzwl 0x62(%rbx),%ecx
  4151fd:	mov    $0x1,%eax
  415202:	shl    %cl,%rax
  415205:	mov    %rax,0x8(%r12)
  41520a:	mov    0x22cfe7(%rip),%rax        # 6421f8 <dataoff>
  415211:	mov    %rax,0x10(%rsp)
  415216:	mov    $0x1,%r15d
  41521c:	mov    $0x0,%r13d
  415222:	mov    (%r14,%r13,8),%rdx
  415226:	mov    %r12,%rsi
  415229:	mov    %rbx,%rdi
  41522c:	callq  414569 <TIFFWriteData>
  415231:	test   %eax,%eax
  415233:	je     4156a3 <TIFFWriteDirectory+0xd92>
  415239:	add    $0x1,%r13
  41523d:	cmp    %r13d,%r15d
  415240:	jg     415222 <TIFFWriteDirectory+0x911>
  415242:	movslq %r15d,%r15
  415245:	imul   0x8(%r12),%r15
  41524b:	mov    %r15,0x8(%r12)
  415250:	mov    0x10(%rsp),%rax
  415255:	mov    %rax,0x10(%r12)
  41525a:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  41525f:	movzwl 0x70(%rbx),%r15d
  415264:	movw   $0x12d,(%r12)
  41526b:	movw   $0x3,0x2(%r12)
  415273:	movzwl 0x62(%rbx),%ecx
  415277:	mov    $0x1,%eax
  41527c:	shl    %cl,%rax
  41527f:	mov    %rax,0x8(%r12)
  415284:	mov    0x22cf6d(%rip),%rax        # 6421f8 <dataoff>
  41528b:	mov    %rax,0x10(%rsp)
  415290:	test   %r15d,%r15d
  415293:	jg     41521c <TIFFWriteDirectory+0x90b>
  415295:	jmp    415242 <TIFFWriteDirectory+0x931>
  415297:	movzwl 0x4(%rbp),%eax
  41529b:	mov    %ax,0x20(%rsp)
  4152a0:	mov    %r14w,(%r12)
  4152a5:	mov    0x8(%rbp),%edx
  4152a8:	mov    %dx,0x2(%r12)
  4152ae:	movzwl %ax,%edx
  4152b1:	mov    %rdx,0x8(%r12)
  4152b6:	cmpl   $0xb,0x8(%rbp)
  4152ba:	ja     414e73 <TIFFWriteDirectory+0x562>
  4152c0:	mov    0x8(%rbp),%edx
  4152c3:	jmpq   *0x41af48(,%rdx,8)
  4152ca:	cmp    $0x1,%ax
  4152ce:	jbe    41533f <TIFFWriteDirectory+0xa2e>
  4152d0:	cmp    $0xffff,%ax
  4152d4:	je     415317 <TIFFWriteDirectory+0xa06>
  4152d6:	movzwl 0x0(%rbp),%esi
  4152da:	lea    0x40(%rsp),%rdx
  4152df:	mov    (%rsp),%rdi
  4152e3:	mov    $0x0,%eax
  4152e8:	callq  4108cd <_TIFFgetfield>
  4152ed:	movzwl 0x0(%rbp),%edx
  4152f1:	mov    0x8(%rbp),%esi
  4152f4:	mov    0x40(%rsp),%r9
  4152f9:	movzwl 0x20(%rsp),%r8d
  4152ff:	mov    %r12,%rcx
  415302:	mov    %rbx,%rdi
  415305:	callq  414611 <TIFFWriteShortArray>
  41530a:	test   %eax,%eax
  41530c:	jne    414e73 <TIFFWriteDirectory+0x562>
  415312:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  415317:	movzwl 0x0(%rbp),%esi
  41531b:	lea    0x40(%rsp),%rcx
  415320:	lea    0x20(%rsp),%rdx
  415325:	mov    (%rsp),%rdi
  415329:	mov    $0x0,%eax
  41532e:	callq  4108cd <_TIFFgetfield>
  415333:	movzwl 0x20(%rsp),%eax
  415338:	mov    %rax,0x8(%r12)
  41533d:	jmp    4152ed <TIFFWriteDirectory+0x9dc>
  41533f:	movzwl 0x0(%rbp),%esi
  415343:	lea    0x40(%rsp),%rdx
  415348:	mov    (%rsp),%rdi
  41534c:	mov    $0x0,%eax
  415351:	callq  4108cd <_TIFFgetfield>
  415356:	cmpw   $0x4d4d,0x1d8(%rbx)
  41535f:	je     415381 <TIFFWriteDirectory+0xa70>
  415361:	movzwl 0x2(%r12),%ecx
  415367:	mov    0x1f0(%rbx),%rdx
  41536e:	movzwl 0x40(%rsp),%eax
  415373:	and    (%rdx,%rcx,8),%rax
  415377:	mov    %rax,0x10(%r12)
  41537c:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  415381:	movzwl 0x2(%r12),%edx
  415387:	mov    0x1f0(%rbx),%rcx
  41538e:	movzwl 0x40(%rsp),%eax
  415393:	and    (%rcx,%rdx,8),%rax
  415397:	mov    0x1e8(%rbx),%rcx
  41539e:	mov    (%rcx,%rdx,4),%ecx
  4153a1:	shl    %cl,%rax
  4153a4:	jmp    415377 <TIFFWriteDirectory+0xa66>
  4153a6:	cmp    $0x1,%ax
  4153aa:	jbe    415444 <TIFFWriteDirectory+0xb33>
  4153b0:	cmp    $0xffff,%ax
  4153b4:	je     41540f <TIFFWriteDirectory+0xafe>
  4153b6:	movzwl 0x0(%rbp),%esi
  4153ba:	lea    0x40(%rsp),%rdx
  4153bf:	mov    (%rsp),%rdi
  4153c3:	mov    $0x0,%eax
  4153c8:	callq  4108cd <_TIFFgetfield>
  4153cd:	mov    0x40(%rsp),%rdx
  4153d2:	movzwl 0x20(%rsp),%eax
  4153d7:	movzwl 0x0(%rbp),%esi
  4153db:	mov    0x8(%rbp),%ecx
  4153de:	mov    %si,(%r12)
  4153e3:	mov    %cx,0x2(%r12)
  4153e9:	movzwl %ax,%ecx
  4153ec:	mov    %rcx,0x8(%r12)
  4153f1:	cmp    $0x1,%ax
  4153f5:	je     415437 <TIFFWriteDirectory+0xb26>
  4153f7:	mov    %r12,%rsi
  4153fa:	mov    %rbx,%rdi
  4153fd:	callq  414569 <TIFFWriteData>
  415402:	test   %eax,%eax
  415404:	je     4156a3 <TIFFWriteDirectory+0xd92>
  41540a:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  41540f:	movzwl 0x0(%rbp),%esi
  415413:	lea    0x40(%rsp),%rcx
  415418:	lea    0x20(%rsp),%rdx
  41541d:	mov    (%rsp),%rdi
  415421:	mov    $0x0,%eax
  415426:	callq  4108cd <_TIFFgetfield>
  41542b:	movzwl 0x20(%rsp),%eax
  415430:	mov    %rax,0x8(%r12)
  415435:	jmp    4153cd <TIFFWriteDirectory+0xabc>
  415437:	mov    (%rdx),%rax
  41543a:	mov    %rax,0x10(%r12)
  41543f:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  415444:	lea    0x10(%r12),%rdx
  415449:	movzwl 0x0(%rbp),%esi
  41544d:	mov    (%rsp),%rdi
  415451:	mov    $0x0,%eax
  415456:	callq  4108cd <_TIFFgetfield>
  41545b:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  415460:	cmp    $0x1,%ax
  415464:	jbe    4154d5 <TIFFWriteDirectory+0xbc4>
  415466:	cmp    $0xffff,%ax
  41546a:	je     4154ad <TIFFWriteDirectory+0xb9c>
  41546c:	movzwl 0x0(%rbp),%esi
  415470:	lea    0x40(%rsp),%rdx
  415475:	mov    (%rsp),%rdi
  415479:	mov    $0x0,%eax
  41547e:	callq  4108cd <_TIFFgetfield>
  415483:	movzwl 0x0(%rbp),%edx
  415487:	mov    0x8(%rbp),%esi
  41548a:	mov    0x40(%rsp),%r9
  41548f:	movzwl 0x20(%rsp),%r8d
  415495:	mov    %r12,%rcx
  415498:	mov    %rbx,%rdi
  41549b:	callq  414698 <TIFFWriteRationalArray>
  4154a0:	test   %eax,%eax
  4154a2:	jne    414e73 <TIFFWriteDirectory+0x562>
  4154a8:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  4154ad:	movzwl 0x0(%rbp),%esi
  4154b1:	lea    0x40(%rsp),%rcx
  4154b6:	lea    0x20(%rsp),%rdx
  4154bb:	mov    (%rsp),%rdi
  4154bf:	mov    $0x0,%eax
  4154c4:	callq  4108cd <_TIFFgetfield>
  4154c9:	movzwl 0x20(%rsp),%eax
  4154ce:	mov    %rax,0x8(%r12)
  4154d3:	jmp    415483 <TIFFWriteDirectory+0xb72>
  4154d5:	movzwl 0x0(%rbp),%esi
  4154d9:	lea    0x40(%rsp),%rdx
  4154de:	mov    (%rsp),%rdi
  4154e2:	mov    $0x0,%eax
  4154e7:	callq  4108cd <_TIFFgetfield>
  4154ec:	movzwl 0x0(%rbp),%edx
  4154f0:	mov    0x8(%rbp),%esi
  4154f3:	movss  0x40(%rsp),%xmm0
  4154f9:	mov    %r12,%rcx
  4154fc:	mov    %rbx,%rdi
  4154ff:	callq  41477a <TIFFWriteRational>
  415504:	test   %eax,%eax
  415506:	jne    414e73 <TIFFWriteDirectory+0x562>
  41550c:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  415511:	cmp    $0x1,%ax
  415515:	jbe    4155af <TIFFWriteDirectory+0xc9e>
  41551b:	cmp    $0xffff,%ax
  41551f:	je     41557a <TIFFWriteDirectory+0xc69>
  415521:	movzwl 0x0(%rbp),%esi
  415525:	lea    0x40(%rsp),%rdx
  41552a:	mov    (%rsp),%rdi
  41552e:	mov    $0x0,%eax
  415533:	callq  4108cd <_TIFFgetfield>
  415538:	mov    0x40(%rsp),%rdx
  41553d:	movzwl 0x20(%rsp),%eax
  415542:	movzwl 0x0(%rbp),%esi
  415546:	mov    0x8(%rbp),%ecx
  415549:	mov    %si,(%r12)
  41554e:	mov    %cx,0x2(%r12)
  415554:	movzwl %ax,%ecx
  415557:	mov    %rcx,0x8(%r12)
  41555c:	cmp    $0x1,%ax
  415560:	je     4155a2 <TIFFWriteDirectory+0xc91>
  415562:	mov    %r12,%rsi
  415565:	mov    %rbx,%rdi
  415568:	callq  414569 <TIFFWriteData>
  41556d:	test   %eax,%eax
  41556f:	je     4156a3 <TIFFWriteDirectory+0xd92>
  415575:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  41557a:	movzwl 0x0(%rbp),%esi
  41557e:	lea    0x40(%rsp),%rcx
  415583:	lea    0x20(%rsp),%rdx
  415588:	mov    (%rsp),%rdi
  41558c:	mov    $0x0,%eax
  415591:	callq  4108cd <_TIFFgetfield>
  415596:	movzwl 0x20(%rsp),%eax
  41559b:	mov    %rax,0x8(%r12)
  4155a0:	jmp    415538 <TIFFWriteDirectory+0xc27>
  4155a2:	mov    (%rdx),%rax
  4155a5:	mov    %rax,0x10(%r12)
  4155aa:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  4155af:	movzwl 0x0(%rbp),%esi
  4155b3:	lea    0x40(%rsp),%rdx
  4155b8:	mov    (%rsp),%rdi
  4155bc:	mov    $0x0,%eax
  4155c1:	callq  4108cd <_TIFFgetfield>
  4155c6:	mov    0x40(%rsp),%rax
  4155cb:	mov    %rax,0x10(%r12)
  4155d0:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  4155d5:	movzwl 0x0(%rbp),%esi
  4155d9:	lea    0x40(%rsp),%rdx
  4155de:	mov    (%rsp),%rdi
  4155e2:	mov    $0x0,%eax
  4155e7:	callq  4108cd <_TIFFgetfield>
  4155ec:	mov    0x40(%rsp),%r8
  4155f1:	movzwl 0x0(%rbp),%eax
  4155f5:	mov    %ax,(%r12)
  4155fa:	movw   $0x2,0x2(%r12)
  415602:	mov    $0x0,%eax
  415607:	mov    $0xffffffffffffffff,%rcx
  41560e:	mov    %r8,%rdi
  415611:	repnz scas %es:(%rdi),%al
  415613:	mov    %rcx,%rdx
  415616:	not    %rdx
  415619:	mov    %rdx,0x8(%r12)
  41561e:	cmp    $0x4,%rdx
  415622:	jbe    41563b <TIFFWriteDirectory+0xd2a>
  415624:	mov    %r8,%rdx
  415627:	mov    %r12,%rsi
  41562a:	mov    %rbx,%rdi
  41562d:	callq  414569 <TIFFWriteData>
  415632:	test   %eax,%eax
  415634:	je     4156a3 <TIFFWriteDirectory+0xd92>
  415636:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  41563b:	lea    0x10(%r12),%rsi
  415640:	mov    %r8,%rdi
  415643:	mov    $0x0,%eax
  415648:	callq  4012d0 <bcopy@plt>
  41564d:	jmpq   414e73 <TIFFWriteDirectory+0x562>
  415652:	mov    0x1c(%rsp),%r13d
  415657:	mov    0x10(%rbx),%rsi
  41565b:	movswl 0x8(%rbx),%edi
  41565f:	mov    $0x0,%edx
  415664:	mov    $0x0,%eax
  415669:	callq  401190 <lseek@plt>
  41566e:	mov    %r13w,0x7e(%rsp)
  415674:	movswl 0x8(%rbx),%edi
  415678:	mov    $0x2,%edx
  41567d:	lea    0x7e(%rsp),%rsi
  415682:	mov    $0x0,%eax
  415687:	callq  401120 <write@plt>
  41568c:	cmp    $0x2,%eax
  41568f:	je     4156c6 <TIFFWriteDirectory+0xdb5>
  415691:	mov    $0x41ad4c,%esi
  415696:	mov    (%rbx),%rdi
  415699:	mov    $0x0,%eax
  41569e:	callq  412a93 <TIFFError>
  4156a3:	mov    0x8(%rsp),%rdi
  4156a8:	callq  4010b0 <free@plt>
  4156ad:	mov    $0x0,%ebp
  4156b2:	mov    %ebp,%eax
  4156b4:	add    $0x88,%rsp
  4156bb:	pop    %rbx
  4156bc:	pop    %rbp
  4156bd:	pop    %r12
  4156bf:	pop    %r13
  4156c1:	pop    %r14
  4156c3:	pop    %r15
  4156c5:	retq   
  4156c6:	movswl 0x8(%rbx),%edi
  4156ca:	mov    0x18(%rsp),%r15d
  4156cf:	mov    %r15d,%edx
  4156d2:	mov    0x8(%rsp),%rsi
  4156d7:	mov    $0x0,%eax
  4156dc:	callq  401120 <write@plt>
  4156e1:	cmp    %r15d,%eax
  4156e4:	je     4156fa <TIFFWriteDirectory+0xde9>
  4156e6:	mov    $0x41acf0,%esi
  4156eb:	mov    (%rbx),%rdi
  4156ee:	mov    $0x0,%eax
  4156f3:	callq  412a93 <TIFFError>
  4156f8:	jmp    4156a3 <TIFFWriteDirectory+0xd92>
  4156fa:	lea    0x18(%rbx),%rsi
  4156fe:	movswl 0x8(%rbx),%edi
  415702:	mov    $0x8,%edx
  415707:	mov    $0x0,%eax
  41570c:	callq  401120 <write@plt>
  415711:	cmp    $0x8,%eax
  415714:	je     41572d <TIFFWriteDirectory+0xe1c>
  415716:	mov    $0x41ad2f,%esi
  41571b:	mov    (%rbx),%rdi
  41571e:	mov    $0x0,%eax
  415723:	callq  412a93 <TIFFError>
  415728:	jmpq   4156a3 <TIFFWriteDirectory+0xd92>
  41572d:	mov    %rbx,%rdi
  415730:	mov    $0x0,%eax
  415735:	callq  410961 <TIFFFreeDirectory>
  41573a:	mov    0x8(%rsp),%rdi
  41573f:	callq  4010b0 <free@plt>
  415744:	andw   $0xfffd,0xe(%rbx)
  415749:	mov    %rbx,%rdi
  41574c:	mov    $0x0,%eax
  415751:	callq  410c5b <TIFFDefaultDirectory>
  415756:	movq   $0x0,0x10(%rbx)
  41575e:	movq   $0x0,0x208(%rbx)
  415769:	mov    $0xffffffffffffffff,%rax
  415770:	mov    %rax,0x1f8(%rbx)
  415777:	mov    %eax,0x204(%rbx)
  41577d:	mov    $0x1,%ebp
  415782:	jmpq   4156b2 <TIFFWriteDirectory+0xda1>

0000000000415787 <DumpModeSeek>:
  415787:	imul   0x290(%rdi),%esi
  41578e:	movslq %esi,%rsi
  415791:	add    %rsi,0x2a8(%rdi)
  415798:	sub    %rsi,0x2b0(%rdi)
  41579f:	mov    $0x1,%eax
  4157a4:	retq   

00000000004157a5 <DumpModeEncode>:
  4157a5:	push   %r13
  4157a7:	push   %r12
  4157a9:	push   %rbp
  4157aa:	push   %rbx
  4157ab:	sub    $0x8,%rsp
  4157af:	mov    %rdi,%rbx
  4157b2:	mov    %rsi,%r13
  4157b5:	mov    %edx,%r12d
  4157b8:	movslq %edx,%rax
  4157bb:	add    0x2b0(%rdi),%rax
  4157c2:	cmp    0x2a0(%rdi),%rax
  4157c9:	jg     4157da <DumpModeEncode+0x35>
  4157cb:	test   %r12d,%r12d
  4157ce:	jg     415848 <DumpModeEncode+0xa3>
  4157d0:	mov    $0x1,%eax
  4157d5:	jmpq   4158fe <DumpModeEncode+0x159>
  4157da:	mov    $0x0,%eax
  4157df:	callq  41425a <TIFFFlushData1>
  4157e4:	test   %eax,%eax
  4157e6:	jne    4157cb <DumpModeEncode+0x26>
  4157e8:	mov    $0xffffffff,%eax
  4157ed:	jmpq   4158fe <DumpModeEncode+0x159>
  4157f2:	test   $0x3,%bpl
  4157f6:	jne    4158ab <DumpModeEncode+0x106>
  4157fc:	mov    %ebp,%esi
  4157fe:	shr    $0x1f,%esi
  415801:	add    %ebp,%esi
  415803:	sar    %esi
  415805:	mov    0x2a8(%rbx),%rdi
  41580c:	callq  413050 <TIFFSwabArrayOfShort>
  415811:	movslq %ebp,%rax
  415814:	add    %rax,0x2a8(%rbx)
  41581b:	mov    %rax,%rdx
  41581e:	add    0x2b0(%rbx),%rdx
  415825:	mov    %rdx,0x2b0(%rbx)
  41582c:	add    %rax,%r13
  41582f:	sub    %ebp,%r12d
  415832:	cmp    0x2a0(%rbx),%rdx
  415839:	jge    4158dd <DumpModeEncode+0x138>
  41583f:	test   %r12d,%r12d
  415842:	jle    4158f9 <DumpModeEncode+0x154>
  415848:	mov    0x2a0(%rbx),%rbp
  41584f:	movslq %r12d,%rax
  415852:	cmp    %rbp,%rax
  415855:	cmovle %r12d,%ebp
  415859:	mov    0x2a8(%rbx),%rsi
  415860:	mov    %ebp,%edx
  415862:	mov    %r13,%rdi
  415865:	mov    $0x0,%eax
  41586a:	callq  4012d0 <bcopy@plt>
  41586f:	testb  $0x10,0xe(%rbx)
  415873:	je     415811 <DumpModeEncode+0x6c>
  415875:	movzwl 0x62(%rbx),%eax
  415879:	cmp    $0x10,%ax
  41587d:	je     4157f2 <DumpModeEncode+0x4d>
  415883:	cmp    $0x20,%ax
  415887:	jne    415811 <DumpModeEncode+0x6c>
  415889:	test   $0xf,%bpl
  41588d:	jne    4158c4 <DumpModeEncode+0x11f>
  41588f:	lea    0x3(%rbp),%esi
  415892:	test   %ebp,%ebp
  415894:	cmovns %ebp,%esi
  415897:	sar    $0x2,%esi
  41589a:	mov    0x2a8(%rbx),%rdi
  4158a1:	callq  413073 <TIFFSwabArrayOfLong>
  4158a6:	jmpq   415811 <DumpModeEncode+0x6c>
  4158ab:	mov    $0x41b040,%ecx
  4158b0:	mov    $0x58,%edx
  4158b5:	mov    $0x41afb8,%esi
  4158ba:	mov    $0x41afc7,%edi
  4158bf:	callq  4011b0 <__assert_fail@plt>
  4158c4:	mov    $0x41b040,%ecx
  4158c9:	mov    $0x5d,%edx
  4158ce:	mov    $0x41afb8,%esi
  4158d3:	mov    $0x41afd4,%edi
  4158d8:	callq  4011b0 <__assert_fail@plt>
  4158dd:	mov    %rbx,%rdi
  4158e0:	mov    $0x0,%eax
  4158e5:	callq  41425a <TIFFFlushData1>
  4158ea:	test   %eax,%eax
  4158ec:	jne    41583f <DumpModeEncode+0x9a>
  4158f2:	mov    $0xffffffff,%eax
  4158f7:	jmp    4158fe <DumpModeEncode+0x159>
  4158f9:	mov    $0x1,%eax
  4158fe:	add    $0x8,%rsp
  415902:	pop    %rbx
  415903:	pop    %rbp
  415904:	pop    %r12
  415906:	pop    %r13
  415908:	retq   

0000000000415909 <DumpModeDecode>:
  415909:	push   %r13
  41590b:	push   %r12
  41590d:	push   %rbp
  41590e:	push   %rbx
  41590f:	sub    $0x8,%rsp
  415913:	mov    %rdi,%rbx
  415916:	movslq %edx,%r12
  415919:	cmp    %r12,0x2b0(%rdi)
  415920:	jl     415974 <DumpModeDecode+0x6b>
  415922:	mov    %rsi,%r13
  415925:	mov    %edx,%ebp
  415927:	mov    0x2a8(%rdi),%rdi
  41592e:	cmp    %rsi,%rdi
  415931:	je     41593d <DumpModeDecode+0x34>
  415933:	mov    $0x0,%eax
  415938:	callq  4012d0 <bcopy@plt>
  41593d:	testb  $0x10,0xe(%rbx)
  415941:	je     415953 <DumpModeDecode+0x4a>
  415943:	movzwl 0x62(%rbx),%eax
  415947:	cmp    $0x10,%ax
  41594b:	je     415994 <DumpModeDecode+0x8b>
  41594d:	cmp    $0x20,%ax
  415951:	je     4159c6 <DumpModeDecode+0xbd>
  415953:	movslq %ebp,%rbp
  415956:	add    %rbp,0x2a8(%rbx)
  41595d:	sub    %r12,0x2b0(%rbx)
  415964:	mov    $0x1,%eax
  415969:	add    $0x8,%rsp
  41596d:	pop    %rbx
  41596e:	pop    %rbp
  41596f:	pop    %r12
  415971:	pop    %r13
  415973:	retq   
  415974:	mov    0x1f8(%rdi),%rdx
  41597b:	mov    $0x41b000,%esi
  415980:	mov    (%rdi),%rdi
  415983:	mov    $0x0,%eax
  415988:	callq  412a93 <TIFFError>
  41598d:	mov    $0x0,%eax
  415992:	jmp    415969 <DumpModeDecode+0x60>
  415994:	test   $0x3,%bpl
  415998:	jne    4159ad <DumpModeDecode+0xa4>
  41599a:	mov    %ebp,%esi
  41599c:	shr    $0x1f,%esi
  41599f:	add    %ebp,%esi
  4159a1:	sar    %esi
  4159a3:	mov    %r13,%rdi
  4159a6:	callq  413050 <TIFFSwabArrayOfShort>
  4159ab:	jmp    415953 <DumpModeDecode+0x4a>
  4159ad:	mov    $0x41b030,%ecx
  4159b2:	mov    $0x87,%edx
  4159b7:	mov    $0x41afb8,%esi
  4159bc:	mov    $0x41afe2,%edi
  4159c1:	callq  4011b0 <__assert_fail@plt>
  4159c6:	test   $0xf,%bpl
  4159ca:	jne    4159e4 <DumpModeDecode+0xdb>
  4159cc:	lea    0x3(%rbp),%esi
  4159cf:	test   %ebp,%ebp
  4159d1:	cmovns %ebp,%esi
  4159d4:	sar    $0x2,%esi
  4159d7:	mov    %r13,%rdi
  4159da:	callq  413073 <TIFFSwabArrayOfLong>
  4159df:	jmpq   415953 <DumpModeDecode+0x4a>
  4159e4:	mov    $0x41b030,%ecx
  4159e9:	mov    $0x8b,%edx
  4159ee:	mov    $0x41afb8,%esi
  4159f3:	mov    $0x41aff0,%edi
  4159f8:	callq  4011b0 <__assert_fail@plt>

00000000004159fd <TIFFInitDumpMode>:
  4159fd:	movq   $0x415909,0x240(%rdi)
  415a08:	movq   $0x415909,0x250(%rdi)
  415a13:	movq   $0x415909,0x260(%rdi)
  415a1e:	movq   $0x4157a5,0x248(%rdi)
  415a29:	movq   $0x4157a5,0x258(%rdi)
  415a34:	movq   $0x4157a5,0x268(%rdi)
  415a3f:	movq   $0x415787,0x278(%rdi)
  415a4a:	mov    $0x1,%eax
  415a4f:	retq   

0000000000415a50 <TIFFInitJPEG>:
  415a50:	mov    $0x1,%eax
  415a55:	retq   

0000000000415a56 <horizontalAccumulate8>:
  415a56:	cmp    %edx,%esi
  415a58:	jle    415ae1 <horizontalAccumulate8+0x8b>
  415a5e:	push   %r12
  415a60:	push   %rbp
  415a61:	push   %rbx
  415a62:	sub    %edx,%esi
  415a64:	movslq %edx,%rcx
  415a67:	lea    -0x4(%rdx),%ebp
  415a6a:	lea    -0x5(%rdx),%ebx
  415a6d:	lea    0x1(%rcx,%rbx,1),%r12
  415a72:	mov    %rcx,%r9
  415a75:	neg    %r9
  415a78:	add    $0x1,%rbx
  415a7c:	mov    %edx,%r11d
  415a7f:	jmp    415acf <horizontalAccumulate8+0x79>
  415a81:	test   %ebp,%ebp
  415a83:	jle    415aa1 <horizontalAccumulate8+0x4b>
  415a85:	lea    (%rdi,%rcx,1),%rax
  415a89:	lea    (%rdi,%r12,1),%r10
  415a8d:	movzbl (%rax,%r9,1),%r8d
  415a92:	add    %r8b,(%rax)
  415a95:	add    $0x1,%rax
  415a99:	cmp    %r10,%rax
  415a9c:	jne    415a8d <horizontalAccumulate8+0x37>
  415a9e:	add    %rbx,%rdi
  415aa1:	movzbl (%rdi),%eax
  415aa4:	add    %al,(%rdi,%rcx,1)
  415aa7:	add    $0x1,%rdi
  415aab:	movzbl (%rdi),%eax
  415aae:	add    %al,(%rdi,%rcx,1)
  415ab1:	add    $0x1,%rdi
  415ab5:	movzbl (%rdi),%eax
  415ab8:	add    %al,(%rdi,%rcx,1)
  415abb:	add    $0x1,%rdi
  415abf:	movzbl (%rdi),%eax
  415ac2:	add    %al,(%rdi,%rcx,1)
  415ac5:	add    $0x1,%rdi
  415ac9:	sub    %edx,%esi
  415acb:	test   %esi,%esi
  415acd:	jle    415adc <horizontalAccumulate8+0x86>
  415acf:	cmp    $0x4,%edx
  415ad2:	ja     415a81 <horizontalAccumulate8+0x2b>
  415ad4:	jmpq   *0x41b050(,%r11,8)
  415adc:	pop    %rbx
  415add:	pop    %rbp
  415ade:	pop    %r12
  415ae0:	retq   
  415ae1:	repz retq 

0000000000415ae3 <horizontalAccumulate16>:
  415ae3:	mov    %esi,%eax
  415ae5:	shr    $0x1f,%eax
  415ae8:	add    %eax,%esi
  415aea:	sar    %esi
  415aec:	cmp    %edx,%esi
  415aee:	jle    415b80 <horizontalAccumulate16+0x9d>
  415af4:	push   %r12
  415af6:	push   %rbp
  415af7:	push   %rbx
  415af8:	sub    %edx,%esi
  415afa:	movslq %edx,%rcx
  415afd:	add    %rcx,%rcx
  415b00:	lea    -0x5(%rdx),%eax
  415b03:	lea    0x2(%rax,%rax,1),%r12
  415b08:	lea    -0x4(%rdx),%ebx
  415b0b:	lea    0x2(%rcx,%rax,2),%rbp
  415b10:	mov    %rcx,%r9
  415b13:	neg    %r9
  415b16:	mov    %edx,%r11d
  415b19:	jmp    415b6e <horizontalAccumulate16+0x8b>
  415b1b:	test   %ebx,%ebx
  415b1d:	jle    415b3c <horizontalAccumulate16+0x59>
  415b1f:	lea    (%rdi,%rcx,1),%rax
  415b23:	lea    (%rdi,%rbp,1),%r10
  415b27:	movzwl (%rax,%r9,1),%r8d
  415b2c:	add    %r8w,(%rax)
  415b30:	add    $0x2,%rax
  415b34:	cmp    %r10,%rax
  415b37:	jne    415b27 <horizontalAccumulate16+0x44>
  415b39:	add    %r12,%rdi
  415b3c:	movzwl (%rdi),%eax
  415b3f:	add    %ax,(%rdi,%rcx,1)
  415b43:	add    $0x2,%rdi
  415b47:	movzwl (%rdi),%eax
  415b4a:	add    %ax,(%rdi,%rcx,1)
  415b4e:	add    $0x2,%rdi
  415b52:	movzwl (%rdi),%eax
  415b55:	add    %ax,(%rdi,%rcx,1)
  415b59:	add    $0x2,%rdi
  415b5d:	movzwl (%rdi),%eax
  415b60:	add    %ax,(%rdi,%rcx,1)
  415b64:	add    $0x2,%rdi
  415b68:	sub    %edx,%esi
  415b6a:	test   %esi,%esi
  415b6c:	jle    415b7b <horizontalAccumulate16+0x98>
  415b6e:	cmp    $0x4,%edx
  415b71:	ja     415b1b <horizontalAccumulate16+0x38>
  415b73:	jmpq   *0x41b078(,%r11,8)
  415b7b:	pop    %rbx
  415b7c:	pop    %rbp
  415b7d:	pop    %r12
  415b7f:	retq   
  415b80:	repz retq 

0000000000415b82 <horizontalDifference8>:
  415b82:	cmp    %edx,%esi
  415b84:	jle    415c18 <horizontalDifference8+0x96>
  415b8a:	push   %r12
  415b8c:	push   %rbp
  415b8d:	push   %rbx
  415b8e:	sub    %edx,%esi
  415b90:	movslq %esi,%rax
  415b93:	lea    -0x1(%rdi,%rax,1),%rax
  415b98:	movslq %edx,%rdi
  415b9b:	lea    -0x4(%rdx),%r12d
  415b9f:	lea    -0x1(%rdi),%rbp
  415ba3:	lea    -0x5(%rdx),%ebx
  415ba6:	sub    %rbx,%rbp
  415ba9:	mov    %rdi,%r9
  415bac:	neg    %r9
  415baf:	not    %rbx
  415bb2:	mov    %edx,%r11d
  415bb5:	jmp    415c06 <horizontalDifference8+0x84>
  415bb7:	test   %r12d,%r12d
  415bba:	jle    415bd8 <horizontalDifference8+0x56>
  415bbc:	lea    (%rax,%rdi,1),%rcx
  415bc0:	lea    (%rax,%rbp,1),%r10
  415bc4:	movzbl (%rcx,%r9,1),%r8d
  415bc9:	sub    %r8b,(%rcx)
  415bcc:	sub    $0x1,%rcx
  415bd0:	cmp    %r10,%rcx
  415bd3:	jne    415bc4 <horizontalDifference8+0x42>
  415bd5:	add    %rbx,%rax
  415bd8:	movzbl (%rax),%ecx
  415bdb:	sub    %cl,(%rax,%rdi,1)
  415bde:	sub    $0x1,%rax
  415be2:	movzbl (%rax),%ecx
  415be5:	sub    %cl,(%rax,%rdi,1)
  415be8:	sub    $0x1,%rax
  415bec:	movzbl (%rax),%ecx
  415bef:	sub    %cl,(%rax,%rdi,1)
  415bf2:	sub    $0x1,%rax
  415bf6:	movzbl (%rax),%ecx
  415bf9:	sub    %cl,(%rax,%rdi,1)
  415bfc:	sub    $0x1,%rax
  415c00:	sub    %edx,%esi
  415c02:	test   %esi,%esi
  415c04:	jle    415c13 <horizontalDifference8+0x91>
  415c06:	cmp    $0x4,%edx
  415c09:	ja     415bb7 <horizontalDifference8+0x35>
  415c0b:	jmpq   *0x41b0a0(,%r11,8)
  415c13:	pop    %rbx
  415c14:	pop    %rbp
  415c15:	pop    %r12
  415c17:	retq   
  415c18:	repz retq 

0000000000415c1a <horizontalDifference16>:
  415c1a:	mov    %esi,%eax
  415c1c:	shr    $0x1f,%eax
  415c1f:	add    %eax,%esi
  415c21:	sar    %esi
  415c23:	cmp    %edx,%esi
  415c25:	jle    415cc9 <horizontalDifference16+0xaf>
  415c2b:	push   %r12
  415c2d:	push   %rbp
  415c2e:	push   %rbx
  415c2f:	sub    %edx,%esi
  415c31:	movslq %esi,%rax
  415c34:	lea    -0x2(%rdi,%rax,2),%rax
  415c39:	movslq %edx,%rdi
  415c3c:	add    %rdi,%rdi
  415c3f:	lea    -0x5(%rdx),%ecx
  415c42:	lea    (%rcx,%rcx,1),%r8
  415c46:	not    %rcx
  415c49:	lea    (%rcx,%rcx,1),%rbx
  415c4d:	lea    -0x4(%rdx),%r12d
  415c51:	lea    -0x2(%rdi),%rbp
  415c55:	sub    %r8,%rbp
  415c58:	mov    %rdi,%r9
  415c5b:	neg    %r9
  415c5e:	mov    %edx,%r11d
  415c61:	jmp    415cb7 <horizontalDifference16+0x9d>
  415c63:	test   %r12d,%r12d
  415c66:	jle    415c85 <horizontalDifference16+0x6b>
  415c68:	lea    (%rax,%rdi,1),%rcx
  415c6c:	lea    (%rax,%rbp,1),%r10
  415c70:	movzwl (%rcx,%r9,1),%r8d
  415c75:	sub    %r8w,(%rcx)
  415c79:	sub    $0x2,%rcx
  415c7d:	cmp    %r10,%rcx
  415c80:	jne    415c70 <horizontalDifference16+0x56>
  415c82:	add    %rbx,%rax
  415c85:	movzwl (%rax),%ecx
  415c88:	sub    %cx,(%rax,%rdi,1)
  415c8c:	sub    $0x2,%rax
  415c90:	movzwl (%rax),%ecx
  415c93:	sub    %cx,(%rax,%rdi,1)
  415c97:	sub    $0x2,%rax
  415c9b:	movzwl (%rax),%ecx
  415c9e:	sub    %cx,(%rax,%rdi,1)
  415ca2:	sub    $0x2,%rax
  415ca6:	movzwl (%rax),%ecx
  415ca9:	sub    %cx,(%rax,%rdi,1)
  415cad:	sub    $0x2,%rax
  415cb1:	sub    %edx,%esi
  415cb3:	test   %esi,%esi
  415cb5:	jle    415cc4 <horizontalDifference16+0xaa>
  415cb7:	cmp    $0x4,%edx
  415cba:	ja     415c63 <horizontalDifference16+0x49>
  415cbc:	jmpq   *0x41b0c8(,%r11,8)
  415cc4:	pop    %rbx
  415cc5:	pop    %rbp
  415cc6:	pop    %r12
  415cc8:	retq   
  415cc9:	repz retq 

0000000000415ccb <cl_hash>:
  415ccb:	lea    0x9cb0(%rdi),%rax
  415cd2:	lea    0xb0(%rdi),%rcx
  415cd9:	mov    $0xffffffffffffffff,%rdx
  415ce0:	mov    %rdx,-0x80(%rax)
  415ce4:	mov    %rdx,-0x78(%rax)
  415ce8:	mov    %rdx,-0x70(%rax)
  415cec:	mov    %rdx,-0x68(%rax)
  415cf0:	mov    %rdx,-0x60(%rax)
  415cf4:	mov    %rdx,-0x58(%rax)
  415cf8:	mov    %rdx,-0x50(%rax)
  415cfc:	mov    %rdx,-0x48(%rax)
  415d00:	mov    %rdx,-0x40(%rax)
  415d04:	mov    %rdx,-0x38(%rax)
  415d08:	mov    %rdx,-0x30(%rax)
  415d0c:	mov    %rdx,-0x28(%rax)
  415d10:	mov    %rdx,-0x20(%rax)
  415d14:	mov    %rdx,-0x18(%rax)
  415d18:	mov    %rdx,-0x10(%rax)
  415d1c:	mov    %rdx,-0x8(%rax)
  415d20:	add    $0xffffffffffffff80,%rax
  415d24:	cmp    %rax,%rcx
  415d27:	jne    415ce0 <cl_hash+0x15>
  415d29:	lea    0x58(%rdi),%rcx
  415d2d:	mov    $0xffffffffffffffff,%rdx
  415d34:	sub    $0x8,%rax
  415d38:	mov    %rdx,(%rax)
  415d3b:	cmp    %rax,%rcx
  415d3e:	jne    415d34 <cl_hash+0x69>
  415d40:	movq   $0x0,0x40(%rdi)
  415d48:	movq   $0x0,0x48(%rdi)
  415d50:	movq   $0x0,0x50(%rdi)
  415d58:	movl   $0x102,0x30(%rdi)
  415d5f:	retq   

0000000000415d60 <LZWCleanup>:
  415d60:	mov    0x288(%rdi),%rax
  415d67:	test   %rax,%rax
  415d6a:	je     415d85 <LZWCleanup+0x25>
  415d6c:	push   %rbx
  415d6d:	mov    %rdi,%rbx
  415d70:	mov    %rax,%rdi
  415d73:	callq  4010b0 <free@plt>
  415d78:	movq   $0x0,0x288(%rbx)
  415d83:	pop    %rbx
  415d84:	retq   
  415d85:	repz retq 

0000000000415d87 <PutNextCode>:
  415d87:	push   %r15
  415d89:	push   %r14
  415d8b:	push   %r13
  415d8d:	push   %r12
  415d8f:	push   %rbp
  415d90:	push   %rbx
  415d91:	sub    $0x8,%rsp
  415d95:	mov    %rdi,%rbp
  415d98:	mov    %esi,%r12d
  415d9b:	mov    0x288(%rdi),%rbx
  415da2:	mov    0x20(%rbx),%rax
  415da6:	movzwl 0x6(%rbx),%r14d
  415dab:	movzwl %r14w,%edx
  415daf:	add    %rax,%rdx
  415db2:	cmp    0x28(%rbx),%rdx
  415db6:	jle    415e87 <PutNextCode+0x100>
  415dbc:	mov    %rax,%r13
  415dbf:	and    $0x7,%r13d
  415dc3:	je     415e7d <PutNextCode+0xf6>
  415dc9:	sar    $0x3,%rax
  415dcd:	mov    %rax,0x2b0(%rdi)
  415dd4:	add    0x298(%rdi),%rax
  415ddb:	mov    %rax,%r15
  415dde:	callq  41425a <TIFFFlushData1>
  415de3:	mov    0x298(%rbp),%rax
  415dea:	movzbl (%r15),%edx
  415dee:	mov    %dl,(%rax)
  415df0:	mov    0x298(%rbp),%rdx
  415df7:	mov    %r13,0x20(%rbx)
  415dfb:	movzwl %r14w,%r14d
  415dff:	lea    -0x8(%r14,%r13,1),%ecx
  415e04:	movzbl (%rdx),%eax
  415e07:	and    0x41b100(%r13),%al
  415e0e:	mov    %r12d,%esi
  415e11:	sar    %cl,%esi
  415e13:	or     %esi,%eax
  415e15:	mov    %al,(%rdx)
  415e17:	lea    0x1(%rdx),%rsi
  415e1b:	cmp    $0x7,%ecx
  415e1e:	jle    415e2f <PutNextCode+0xa8>
  415e20:	sub    $0x8,%ecx
  415e23:	lea    0x2(%rdx),%rsi
  415e27:	mov    %r12d,%eax
  415e2a:	sar    %cl,%eax
  415e2c:	mov    %al,0x1(%rdx)
  415e2f:	test   %ecx,%ecx
  415e31:	je     415e4f <PutNextCode+0xc8>
  415e33:	movslq %ecx,%rax
  415e36:	movzbl 0x41b110(%rax),%eax
  415e3d:	and    %eax,%r12d
  415e40:	mov    $0x8,%eax
  415e45:	sub    %ecx,%eax
  415e47:	mov    %eax,%ecx
  415e49:	shl    %cl,%r12d
  415e4c:	mov    %r12b,(%rsi)
  415e4f:	movzwl 0x6(%rbx),%eax
  415e53:	add    %rax,0x50(%rbx)
  415e57:	add    0x20(%rbx),%rax
  415e5b:	mov    %rax,0x20(%rbx)
  415e5f:	add    $0x7,%rax
  415e63:	sar    $0x3,%rax
  415e67:	mov    %rax,0x2b0(%rbp)
  415e6e:	add    $0x8,%rsp
  415e72:	pop    %rbx
  415e73:	pop    %rbp
  415e74:	pop    %r12
  415e76:	pop    %r13
  415e78:	pop    %r14
  415e7a:	pop    %r15
  415e7c:	retq   
  415e7d:	callq  41425a <TIFFFlushData1>
  415e82:	jmpq   415df0 <PutNextCode+0x69>
  415e87:	mov    %rax,%rdx
  415e8a:	sar    $0x3,%rdx
  415e8e:	add    0x298(%rdi),%rdx
  415e95:	and    $0x7,%eax
  415e98:	mov    %rax,%r13
  415e9b:	jmpq   415dfb <PutNextCode+0x74>

0000000000415ea0 <LZWEncode>:
  415ea0:	push   %r15
  415ea2:	push   %r14
  415ea4:	push   %r13
  415ea6:	push   %r12
  415ea8:	push   %rbp
  415ea9:	push   %rbx
  415eaa:	sub    $0x18,%rsp
  415eae:	mov    %rdi,0x8(%rsp)
  415eb3:	mov    0x288(%rdi),%r12
  415eba:	test   %r12,%r12
  415ebd:	je     416131 <LZWEncode+0x291>
  415ec3:	mov    %rsi,%r13
  415ec6:	mov    %edx,%ebx
  415ec8:	mov    (%r12),%esi
  415ecc:	cmp    $0xffffffff,%esi
  415ecf:	jne    415ed5 <LZWEncode+0x35>
  415ed1:	test   %edx,%edx
  415ed3:	jg     415ee7 <LZWEncode+0x47>
  415ed5:	test   %ebx,%ebx
  415ed7:	jle    416119 <LZWEncode+0x279>
  415edd:	lea    -0x1(%rbx),%eax
  415ee0:	lea    0x1(%r13,%rax,1),%r15
  415ee5:	jmp    415f28 <LZWEncode+0x88>
  415ee7:	mov    $0x100,%esi
  415eec:	callq  415d87 <PutNextCode>
  415ef1:	movzbl 0x0(%r13),%esi
  415ef6:	sub    $0x1,%ebx
  415ef9:	addq   $0x1,0x48(%r12)
  415eff:	lea    0x1(%r13),%r13
  415f03:	jmp    415ed5 <LZWEncode+0x35>
  415f05:	movslq %ebx,%rbx
  415f08:	movswl 0x9cb0(%r12,%rbx,2),%esi
  415f11:	jmp    415f1f <LZWEncode+0x7f>
  415f13:	movslq %ebx,%rbx
  415f16:	movswl 0x9cb0(%r12,%rbx,2),%esi
  415f1f:	cmp    %r13,%r15
  415f22:	je     416119 <LZWEncode+0x279>
  415f28:	add    $0x1,%r13
  415f2c:	movzbl -0x1(%r13),%ebp
  415f31:	movzbl %bpl,%r14d
  415f35:	addq   $0x1,0x48(%r12)
  415f3b:	movzbl %bpl,%ebp
  415f3f:	shl    $0xc,%rbp
  415f43:	movslq %esi,%rax
  415f46:	add    %rax,%rbp
  415f49:	mov    %r14d,%ecx
  415f4c:	shl    $0x4,%ecx
  415f4f:	mov    %ecx,%ebx
  415f51:	xor    %esi,%ebx
  415f53:	movslq %ebx,%rax
  415f56:	mov    0x58(%r12,%rax,8),%rax
  415f5b:	cmp    %rbp,%rax
  415f5e:	je     415f05 <LZWEncode+0x65>
  415f60:	test   %rax,%rax
  415f63:	js     415f95 <LZWEncode+0xf5>
  415f65:	mov    $0x138b,%edx
  415f6a:	sub    %ebx,%edx
  415f6c:	cmp    %esi,%ecx
  415f6e:	mov    $0x1,%eax
  415f73:	cmove  %eax,%edx
  415f76:	sub    %edx,%ebx
  415f78:	lea    0x138b(%rbx),%eax
  415f7e:	test   %ebx,%ebx
  415f80:	cmovs  %eax,%ebx
  415f83:	movslq %ebx,%rax
  415f86:	mov    0x58(%r12,%rax,8),%rax
  415f8b:	cmp    %rbp,%rax
  415f8e:	je     415f13 <LZWEncode+0x73>
  415f90:	test   %rax,%rax
  415f93:	jns    415f76 <LZWEncode+0xd6>
  415f95:	mov    0x8(%rsp),%rdi
  415f9a:	callq  415d87 <PutNextCode>
  415f9f:	mov    0x30(%r12),%edx
  415fa4:	lea    0x1(%rdx),%eax
  415fa7:	mov    %eax,0x30(%r12)
  415fac:	movslq %ebx,%rbx
  415faf:	mov    %dx,0x9cb0(%r12,%rbx,2)
  415fb8:	mov    %rbp,0x58(%r12,%rbx,8)
  415fbd:	cmp    $0xffe,%eax
  415fc2:	je     41600c <LZWEncode+0x16c>
  415fc4:	cmp    0x18(%r12),%eax
  415fc9:	jle    41606a <LZWEncode+0x1ca>
  415fcf:	movzwl 0x6(%r12),%eax
  415fd5:	lea    0x1(%rax),%ecx
  415fd8:	mov    %cx,0x6(%r12)
  415fde:	cmp    $0xc,%cx
  415fe2:	ja     416051 <LZWEncode+0x1b1>
  415fe4:	mov    $0x1,%eax
  415fe9:	shl    %cl,%eax
  415feb:	lea    -0x1(%rax),%edx
  415fee:	mov    %edx,0x18(%r12)
  415ff3:	mov    %r14d,%esi
  415ff6:	testb  $0x2,0x4(%r12)
  415ffc:	je     415f1f <LZWEncode+0x7f>
  416002:	mov    %eax,0x18(%r12)
  416007:	jmpq   415f1f <LZWEncode+0x7f>
  41600c:	mov    %r12,%rdi
  41600f:	callq  415ccb <cl_hash>
  416014:	mov    $0x100,%esi
  416019:	mov    0x8(%rsp),%rdi
  41601e:	callq  415d87 <PutNextCode>
  416023:	movw   $0x9,0x6(%r12)
  41602b:	movl   $0x1ff,0x18(%r12)
  416034:	mov    %r14d,%esi
  416037:	testb  $0x2,0x4(%r12)
  41603d:	je     415f1f <LZWEncode+0x7f>
  416043:	movl   $0x200,0x18(%r12)
  41604c:	jmpq   415f1f <LZWEncode+0x7f>
  416051:	mov    $0x41b0f0,%ecx
  416056:	mov    $0x2d2,%edx
  41605b:	mov    $0x41b119,%esi
  416060:	mov    $0x41b123,%edi
  416065:	callq  4011b0 <__assert_fail@plt>
  41606a:	mov    %r14d,%esi
  41606d:	mov    0x38(%r12),%rax
  416072:	cmp    %rax,0x48(%r12)
  416077:	jl     415f1f <LZWEncode+0x7f>
  41607d:	mov    0x8(%rsp),%rax
  416082:	mov    0x288(%rax),%rbx
  416089:	mov    0x48(%rbx),%rdx
  41608d:	lea    0x2710(%rdx),%rax
  416094:	mov    %rax,0x38(%rbx)
  416098:	cmp    $0x7fffff,%rdx
  41609f:	jle    4160bd <LZWEncode+0x21d>
  4160a1:	mov    0x50(%rbx),%rcx
  4160a5:	sar    $0x8,%rcx
  4160a9:	mov    $0x7fffffff,%eax
  4160ae:	test   %rcx,%rcx
  4160b1:	je     4160ca <LZWEncode+0x22a>
  4160b3:	mov    %rdx,%rax
  4160b6:	cqto   
  4160b8:	idiv   %rcx
  4160bb:	jmp    4160ca <LZWEncode+0x22a>
  4160bd:	mov    %rdx,%rax
  4160c0:	shl    $0x8,%rax
  4160c4:	cqto   
  4160c6:	idivq  0x50(%rbx)
  4160ca:	cmp    %rax,0x40(%rbx)
  4160ce:	jge    4160dc <LZWEncode+0x23c>
  4160d0:	mov    %rax,0x40(%rbx)
  4160d4:	mov    %r14d,%esi
  4160d7:	jmpq   415f1f <LZWEncode+0x7f>
  4160dc:	mov    %rbx,%rdi
  4160df:	callq  415ccb <cl_hash>
  4160e4:	mov    $0x100,%esi
  4160e9:	mov    0x8(%rsp),%rdi
  4160ee:	callq  415d87 <PutNextCode>
  4160f3:	movw   $0x9,0x6(%rbx)
  4160f9:	movl   $0x1ff,0x18(%rbx)
  416100:	mov    %r14d,%esi
  416103:	testb  $0x2,0x4(%rbx)
  416107:	je     415f1f <LZWEncode+0x7f>
  41610d:	movl   $0x200,0x18(%rbx)
  416114:	jmpq   415f1f <LZWEncode+0x7f>
  416119:	mov    %esi,(%r12)
  41611d:	mov    $0x1,%eax
  416122:	add    $0x18,%rsp
  416126:	pop    %rbx
  416127:	pop    %rbp
  416128:	pop    %r12
  41612a:	pop    %r13
  41612c:	pop    %r14
  41612e:	pop    %r15
  416130:	retq   
  416131:	mov    $0x0,%eax
  416136:	jmp    416122 <LZWEncode+0x282>

0000000000416138 <LZWEncodePredTile>:
  416138:	push   %r15
  41613a:	push   %r14
  41613c:	push   %r13
  41613e:	push   %r12
  416140:	push   %rbp
  416141:	push   %rbx
  416142:	sub    $0x18,%rsp
  416146:	mov    %rdi,%r14
  416149:	mov    %rsi,%r15
  41614c:	mov    %edx,%r13d
  41614f:	mov    %ecx,0xc(%rsp)
  416153:	mov    0x288(%rdi),%rbx
  41615a:	test   %edx,%edx
  41615c:	jle    416184 <LZWEncodePredTile+0x4c>
  41615e:	mov    %rsi,%r12
  416161:	mov    %edx,%ebp
  416163:	movzwl 0x8(%rbx),%edx
  416167:	movzwl 0xa(%rbx),%esi
  41616b:	mov    %r12,%rdi
  41616e:	callq  *0x10(%rbx)
  416171:	movzwl 0xa(%rbx),%eax
  416175:	movzwl %ax,%edx
  416178:	sub    %edx,%ebp
  41617a:	movzwl %ax,%eax
  41617d:	add    %rax,%r12
  416180:	test   %ebp,%ebp
  416182:	jg     416163 <LZWEncodePredTile+0x2b>
  416184:	mov    0xc(%rsp),%ecx
  416188:	mov    %r13d,%edx
  41618b:	mov    %r15,%rsi
  41618e:	mov    %r14,%rdi
  416191:	callq  415ea0 <LZWEncode>
  416196:	add    $0x18,%rsp
  41619a:	pop    %rbx
  41619b:	pop    %rbp
  41619c:	pop    %r12
  41619e:	pop    %r13
  4161a0:	pop    %r14
  4161a2:	pop    %r15
  4161a4:	retq   

00000000004161a5 <LZWEncodePredRow>:
  4161a5:	push   %r13
  4161a7:	push   %r12
  4161a9:	push   %rbp
  4161aa:	push   %rbx
  4161ab:	sub    $0x8,%rsp
  4161af:	mov    %rdi,%rbx
  4161b2:	mov    %rsi,%rbp
  4161b5:	mov    %edx,%r12d
  4161b8:	mov    %ecx,%r13d
  4161bb:	mov    0x288(%rdi),%rax
  4161c2:	movzwl 0x8(%rax),%edx
  4161c6:	mov    %r12d,%esi
  4161c9:	mov    %rbp,%rdi
  4161cc:	callq  *0x10(%rax)
  4161cf:	mov    %r13d,%ecx
  4161d2:	mov    %r12d,%edx
  4161d5:	mov    %rbp,%rsi
  4161d8:	mov    %rbx,%rdi
  4161db:	callq  415ea0 <LZWEncode>
  4161e0:	add    $0x8,%rsp
  4161e4:	pop    %rbx
  4161e5:	pop    %rbp
  4161e6:	pop    %r12
  4161e8:	pop    %r13
  4161ea:	retq   

00000000004161eb <LZWPostEncode>:
  4161eb:	push   %rbp
  4161ec:	push   %rbx
  4161ed:	sub    $0x8,%rsp
  4161f1:	mov    %rdi,%rbx
  4161f4:	mov    0x288(%rdi),%rbp
  4161fb:	mov    0x0(%rbp),%esi
  4161fe:	cmp    $0xffffffff,%esi
  416201:	je     41620f <LZWPostEncode+0x24>
  416203:	callq  415d87 <PutNextCode>
  416208:	movl   $0xffffffff,0x0(%rbp)
  41620f:	mov    $0x101,%esi
  416214:	mov    %rbx,%rdi
  416217:	callq  415d87 <PutNextCode>
  41621c:	mov    $0x1,%eax
  416221:	add    $0x8,%rsp
  416225:	pop    %rbx
  416226:	pop    %rbp
  416227:	retq   

0000000000416228 <LZWCheckPredictor>:
  416228:	push   %rbx
  416229:	mov    %rsi,%rbx
  41622c:	movzwl 0x72(%rdi),%eax
  416230:	cmp    $0x1,%ax
  416234:	je     416285 <LZWCheckPredictor+0x5d>
  416236:	cmp    $0x2,%ax
  41623a:	jne    4162ad <LZWCheckPredictor+0x85>
  41623c:	mov    $0x1,%eax
  416241:	cmpw   $0x1,0x9a(%rdi)
  416249:	je     41627b <LZWCheckPredictor+0x53>
  41624b:	mov    %ax,0x8(%rbx)
  41624f:	movzwl 0x62(%rdi),%eax
  416253:	cmp    $0x8,%ax
  416257:	je     416281 <LZWCheckPredictor+0x59>
  416259:	cmp    $0x10,%ax
  41625d:	je     4162a7 <LZWCheckPredictor+0x7f>
  41625f:	movzwl %ax,%edx
  416262:	mov    $0x41b178,%esi
  416267:	mov    (%rdi),%rdi
  41626a:	mov    $0x0,%eax
  41626f:	callq  412a93 <TIFFError>
  416274:	mov    $0x0,%eax
  416279:	jmp    4162c7 <LZWCheckPredictor+0x9f>
  41627b:	movzwl 0x70(%rdi),%eax
  41627f:	jmp    41624b <LZWCheckPredictor+0x23>
  416281:	mov    %rdx,0x10(%rbx)
  416285:	mov    $0x1,%eax
  41628a:	cmpq   $0x0,0x10(%rbx)
  41628f:	je     4162c7 <LZWCheckPredictor+0x9f>
  416291:	testb  $0x80,0xe(%rdi)
  416295:	jne    4162c9 <LZWCheckPredictor+0xa1>
  416297:	callq  412fcd <TIFFScanlineSize>
  41629c:	mov    %ax,0xa(%rbx)
  4162a0:	mov    $0x1,%eax
  4162a5:	jmp    4162c7 <LZWCheckPredictor+0x9f>
  4162a7:	mov    %rcx,0x10(%rbx)
  4162ab:	jmp    416285 <LZWCheckPredictor+0x5d>
  4162ad:	movzwl %ax,%edx
  4162b0:	mov    $0x41b1c0,%esi
  4162b5:	mov    (%rdi),%rdi
  4162b8:	mov    $0x0,%eax
  4162bd:	callq  412a93 <TIFFError>
  4162c2:	mov    $0x0,%eax
  4162c7:	pop    %rbx
  4162c8:	retq   
  4162c9:	callq  4133ab <TIFFTileRowSize>
  4162ce:	mov    %ax,0xa(%rbx)
  4162d2:	mov    $0x1,%eax
  4162d7:	jmp    4162c7 <LZWCheckPredictor+0x9f>

00000000004162d9 <LZWPreEncode>:
  4162d9:	push   %rbp
  4162da:	push   %rbx
  4162db:	sub    $0x8,%rsp
  4162df:	mov    %rdi,%rbp
  4162e2:	mov    0x288(%rdi),%rbx
  4162e9:	test   %rbx,%rbx
  4162ec:	je     416345 <LZWPreEncode+0x6c>
  4162ee:	movq   $0x2710,0x38(%rbx)
  4162f6:	movw   $0x9,0x6(%rbx)
  4162fc:	movl   $0x1ff,0x18(%rbx)
  416303:	testb  $0x2,0x4(%rbx)
  416307:	je     416310 <LZWPreEncode+0x37>
  416309:	movl   $0x200,0x18(%rbx)
  416310:	mov    %rbx,%rdi
  416313:	callq  415ccb <cl_hash>
  416318:	movq   $0x0,0x20(%rbx)
  416320:	mov    0x2a0(%rbp),%rax
  416327:	lea    -0xb(,%rax,8),%rax
  41632f:	mov    %rax,0x28(%rbx)
  416333:	movl   $0xffffffff,(%rbx)
  416339:	mov    $0x1,%eax
  41633e:	add    $0x8,%rsp
  416342:	pop    %rbx
  416343:	pop    %rbp
  416344:	retq   
  416345:	mov    $0xc3c8,%edi
  41634a:	mov    $0x0,%eax
  41634f:	callq  401270 <malloc@plt>
  416354:	mov    %rax,%rbx
  416357:	mov    %rax,0x288(%rbp)
  41635e:	test   %rax,%rax
  416361:	je     4163bb <LZWPreEncode+0xe2>
  416363:	movw   $0x0,0x4(%rax)
  416369:	movq   $0x0,0x10(%rax)
  416371:	mov    $0x415c1a,%ecx
  416376:	mov    $0x415b82,%edx
  41637b:	mov    %rax,%rsi
  41637e:	mov    %rbp,%rdi
  416381:	callq  416228 <LZWCheckPredictor>
  416386:	test   %eax,%eax
  416388:	je     41633e <LZWPreEncode+0x65>
  41638a:	cmpq   $0x0,0x10(%rbx)
  41638f:	je     4162ee <LZWPreEncode+0x15>
  416395:	movq   $0x4161a5,0x248(%rbp)
  4163a0:	movq   $0x416138,0x258(%rbp)
  4163ab:	movq   $0x416138,0x268(%rbp)
  4163b6:	jmpq   4162ee <LZWPreEncode+0x15>
  4163bb:	mov    $0x41b13d,%esi
  4163c0:	mov    $0x41b15a,%edi
  4163c5:	mov    $0x0,%eax
  4163ca:	callq  412a93 <TIFFError>
  4163cf:	mov    $0x0,%eax
  4163d4:	jmpq   41633e <LZWPreEncode+0x65>

00000000004163d9 <GetNextCode>:
  4163d9:	mov    0x288(%rdi),%r8
  4163e0:	mov    0x20(%r8),%r9
  4163e4:	cmp    0x28(%r8),%r9
  4163e8:	jg     416463 <GetNextCode+0x8a>
  4163ea:	movzwl 0x6(%r8),%esi
  4163ef:	mov    %r9,%rdx
  4163f2:	sar    $0x3,%rdx
  4163f6:	add    0x298(%rdi),%rdx
  4163fd:	mov    %r9,%r11
  416400:	and    $0x7,%r11d
  416404:	testb  $0x2,0x4(%r8)
  416409:	je     416489 <GetNextCode+0xb0>
  41640b:	movzbl (%rdx),%eax
  41640e:	mov    %r11d,%ecx
  416411:	sar    %cl,%eax
  416413:	mov    %eax,%r10d
  416416:	mov    $0x8,%ecx
  41641b:	sub    %r11,%rcx
  41641e:	movzwl %si,%edi
  416421:	sub    %ecx,%edi
  416423:	lea    0x1(%rdx),%rax
  416427:	cmp    $0x7,%edi
  41642a:	jle    416444 <GetNextCode+0x6b>
  41642c:	lea    0x2(%rdx),%rax
  416430:	movzbl 0x1(%rdx),%edx
  416434:	shl    %cl,%edx
  416436:	or     %edx,%r10d
  416439:	mov    $0x10,%ecx
  41643e:	sub    %r11,%rcx
  416441:	sub    $0x8,%edi
  416444:	movslq %edi,%rdi
  416447:	movzbl (%rax),%eax
  41644a:	and    0x41b110(%rdi),%al
  416450:	movzbl %al,%eax
  416453:	shl    %cl,%eax
  416455:	or     %r10d,%eax
  416458:	movzwl %si,%esi
  41645b:	add    %r9,%rsi
  41645e:	mov    %rsi,0x20(%r8)
  416462:	retq   
  416463:	sub    $0x8,%rsp
  416467:	mov    0x204(%rdi),%edx
  41646d:	mov    $0x41b1e8,%esi
  416472:	mov    (%rdi),%rdi
  416475:	mov    $0x0,%eax
  41647a:	callq  413526 <TIFFWarning>
  41647f:	mov    $0x101,%eax
  416484:	add    $0x8,%rsp
  416488:	retq   
  416489:	mov    $0x8,%ecx
  41648e:	sub    %r11,%rcx
  416491:	movzbl (%rdx),%edi
  416494:	and    0x41b110(%rcx),%dil
  41649b:	movzbl %dil,%edi
  41649f:	movzwl %si,%r10d
  4164a3:	sub    %ecx,%r10d
  4164a6:	lea    0x1(%rdx),%rcx
  4164aa:	cmp    $0x7,%r10d
  4164ae:	jle    4164c1 <GetNextCode+0xe8>
  4164b0:	shl    $0x8,%edi
  4164b3:	lea    0x2(%rdx),%rcx
  4164b7:	movzbl 0x1(%rdx),%eax
  4164bb:	or     %eax,%edi
  4164bd:	sub    $0x8,%r10d
  4164c1:	movslq %r10d,%rdx
  4164c4:	movzbl (%rcx),%eax
  4164c7:	and    0x41b100(%rdx),%al
  4164cd:	movzbl %al,%eax
  4164d0:	mov    $0x8,%ecx
  4164d5:	sub    %r10d,%ecx
  4164d8:	shr    %cl,%eax
  4164da:	mov    %r10d,%ecx
  4164dd:	shl    %cl,%edi
  4164df:	or     %edi,%eax
  4164e1:	jmpq   416458 <GetNextCode+0x7f>

00000000004164e6 <LZWDecode>:
  4164e6:	push   %r15
  4164e8:	push   %r14
  4164ea:	push   %r13
  4164ec:	push   %r12
  4164ee:	push   %rbp
  4164ef:	push   %rbx
  4164f0:	sub    $0x18,%rsp
  4164f4:	mov    %rdi,%r15
  4164f7:	mov    %rsi,%r13
  4164fa:	mov    %edx,%ebx
  4164fc:	mov    0x288(%rdi),%r12
  416503:	mov    0x3ae0(%r12),%rbp
  41650b:	testb  $0x1,0x4(%r12)
  416511:	je     41653c <LZWDecode+0x56>
  416513:	lea    0x374e(%r12),%rdx
  41651b:	sub    $0x1,%ebx
  41651e:	js     416586 <LZWDecode+0xa0>
  416520:	sub    $0x1,%rbp
  416524:	add    $0x1,%r13
  416528:	movzbl 0x0(%rbp),%eax
  41652c:	mov    %al,-0x1(%r13)
  416530:	cmp    %rdx,%rbp
  416533:	ja     41651b <LZWDecode+0x35>
  416535:	andw   $0xfffe,0x4(%r12)
  41653c:	mov    (%r12),%eax
  416540:	mov    %eax,0x8(%rsp)
  416544:	mov    0x3ae8(%r12),%eax
  41654c:	mov    %eax,0xc(%rsp)
  416550:	lea    0x374e(%r12),%r14
  416558:	test   %ebx,%ebx
  41655a:	jg     4166da <LZWDecode+0x1f4>
  416560:	mov    %rbp,0x3ae0(%r12)
  416568:	mov    0x8(%rsp),%eax
  41656c:	mov    %eax,(%r12)
  416570:	mov    0xc(%rsp),%eax
  416574:	mov    %eax,0x3ae8(%r12)
  41657c:	mov    $0x1,%eax
  416581:	jmpq   41662b <LZWDecode+0x145>
  416586:	mov    %rbp,0x3ae0(%r12)
  41658e:	mov    $0x1,%eax
  416593:	jmpq   41662b <LZWDecode+0x145>
  416598:	lea    0x38(%r12),%rdi
  41659d:	mov    $0x2716,%esi
  4165a2:	mov    $0x0,%eax
  4165a7:	callq  4012f0 <bzero@plt>
  4165ac:	movl   $0x102,0x30(%r12)
  4165b5:	movw   $0x9,0x6(%r12)
  4165bd:	movl   $0x1fe,0x18(%r12)
  4165c6:	testb  $0x2,0x4(%r12)
  4165cc:	je     4165d7 <LZWDecode+0xf1>
  4165ce:	movl   $0x1ff,0x18(%r12)
  4165d7:	mov    %r15,%rdi
  4165da:	callq  4163d9 <GetNextCode>
  4165df:	cmp    $0x101,%eax
  4165e4:	jne    41663a <LZWDecode+0x154>
  4165e6:	mov    %rbp,0x3ae0(%r12)
  4165ee:	mov    0x8(%rsp),%eax
  4165f2:	mov    %eax,(%r12)
  4165f6:	mov    0xc(%rsp),%eax
  4165fa:	mov    %eax,0x3ae8(%r12)
  416602:	mov    $0x1,%eax
  416607:	test   %ebx,%ebx
  416609:	jle    41662b <LZWDecode+0x145>
  41660b:	mov    0x1f8(%r15),%rdx
  416612:	mov    %ebx,%ecx
  416614:	mov    $0x41b220,%esi
  416619:	mov    (%r15),%rdi
  41661c:	mov    $0x0,%eax
  416621:	callq  412a93 <TIFFError>
  416626:	mov    $0x0,%eax
  41662b:	add    $0x18,%rsp
  41662f:	pop    %rbx
  416630:	pop    %rbp
  416631:	pop    %r12
  416633:	pop    %r13
  416635:	pop    %r14
  416637:	pop    %r15
  416639:	retq   
  41663a:	mov    %al,0x0(%r13)
  41663e:	sub    $0x1,%ebx
  416641:	mov    %eax,0x8(%rsp)
  416645:	mov    %eax,0xc(%rsp)
  416649:	lea    0x1(%r13),%r13
  41664d:	jmpq   4166d2 <LZWDecode+0x1ec>
  416652:	orw    $0x1,0x4(%r12)
  416659:	mov    %rdx,%rbp
  41665c:	mov    0x30(%r12),%edx
  416661:	cmp    $0xffe,%edx
  416667:	jg     4166ce <LZWDecode+0x1e8>
  416669:	movslq %edx,%rcx
  41666c:	movzwl 0x8(%rsp),%edi
  416671:	mov    %di,0x38(%r12,%rcx,2)
  416677:	mov    %sil,0x274e(%r12,%rcx,1)
  41667f:	add    $0x1,%edx
  416682:	mov    %edx,0x30(%r12)
  416687:	mov    %eax,0x8(%rsp)
  41668b:	cmp    0x18(%r12),%edx
  416690:	jle    4166d2 <LZWDecode+0x1ec>
  416692:	movzwl 0x6(%r12),%esi
  416698:	lea    0x1(%rsi),%ecx
  41669b:	cmp    $0xc,%cx
  41669f:	mov    $0xc,%edx
  4166a4:	cmova  %edx,%ecx
  4166a7:	mov    %cx,0x6(%r12)
  4166ad:	mov    $0x1,%edx
  4166b2:	shl    %cl,%edx
  4166b4:	lea    -0x2(%rdx),%ecx
  4166b7:	mov    %ecx,0x18(%r12)
  4166bc:	testb  $0x2,0x4(%r12)
  4166c2:	je     4166d2 <LZWDecode+0x1ec>
  4166c4:	sub    $0x1,%edx
  4166c7:	mov    %edx,0x18(%r12)
  4166cc:	jmp    4166d2 <LZWDecode+0x1ec>
  4166ce:	mov    %eax,0x8(%rsp)
  4166d2:	test   %ebx,%ebx
  4166d4:	jle    416560 <LZWDecode+0x7a>
  4166da:	mov    %r15,%rdi
  4166dd:	callq  4163d9 <GetNextCode>
  4166e2:	cmp    $0x101,%eax
  4166e7:	je     4165e6 <LZWDecode+0x100>
  4166ed:	cmp    $0x100,%eax
  4166f2:	je     416598 <LZWDecode+0xb2>
  4166f8:	mov    %eax,%edx
  4166fa:	cmp    %eax,0x30(%r12)
  4166ff:	jg     416712 <LZWDecode+0x22c>
  416701:	movzbl 0xc(%rsp),%esi
  416706:	mov    %sil,0x0(%rbp)
  41670a:	lea    0x1(%rbp),%rbp
  41670e:	mov    0x8(%rsp),%edx
  416712:	cmp    $0xff,%edx
  416718:	jle    41673b <LZWDecode+0x255>
  41671a:	add    $0x1,%rbp
  41671e:	movslq %edx,%rdx
  416721:	movzbl 0x274e(%r12,%rdx,1),%ecx
  41672a:	mov    %cl,-0x1(%rbp)
  41672d:	movswl 0x38(%r12,%rdx,2),%edx
  416733:	cmp    $0xff,%edx
  416739:	jg     41671a <LZWDecode+0x234>
  41673b:	movslq %edx,%rdx
  41673e:	movzbl 0x274e(%r12,%rdx,1),%esi
  416747:	movzbl %sil,%edi
  41674b:	mov    %edi,0xc(%rsp)
  41674f:	lea    0x1(%rbp),%rdx
  416753:	mov    %sil,0x0(%rbp)
  416757:	sub    $0x1,%ebx
  41675a:	js     416652 <LZWDecode+0x16c>
  416760:	sub    $0x1,%rdx
  416764:	add    $0x1,%r13
  416768:	movzbl (%rdx),%ecx
  41676b:	mov    %cl,-0x1(%r13)
  41676f:	cmp    %r14,%rdx
  416772:	ja     416757 <LZWDecode+0x271>
  416774:	mov    %rdx,%rbp
  416777:	jmpq   41665c <LZWDecode+0x176>

000000000041677c <LZWDecodePredTile>:
  41677c:	push   %r12
  41677e:	push   %rbp
  41677f:	push   %rbx
  416780:	mov    %rsi,%r12
  416783:	mov    %edx,%ebp
  416785:	mov    0x288(%rdi),%rbx
  41678c:	callq  4164e6 <LZWDecode>
  416791:	test   %eax,%eax
  416793:	je     4167bf <LZWDecodePredTile+0x43>
  416795:	test   %ebp,%ebp
  416797:	jle    4167c4 <LZWDecodePredTile+0x48>
  416799:	movzwl 0x8(%rbx),%edx
  41679d:	movzwl 0xa(%rbx),%esi
  4167a1:	mov    %r12,%rdi
  4167a4:	callq  *0x10(%rbx)
  4167a7:	movzwl 0xa(%rbx),%eax
  4167ab:	movzwl %ax,%edx
  4167ae:	sub    %edx,%ebp
  4167b0:	movzwl %ax,%eax
  4167b3:	add    %rax,%r12
  4167b6:	test   %ebp,%ebp
  4167b8:	jg     416799 <LZWDecodePredTile+0x1d>
  4167ba:	mov    $0x1,%eax
  4167bf:	pop    %rbx
  4167c0:	pop    %rbp
  4167c1:	pop    %r12
  4167c3:	retq   
  4167c4:	mov    $0x1,%eax
  4167c9:	jmp    4167bf <LZWDecodePredTile+0x43>

00000000004167cb <LZWDecodePredRow>:
  4167cb:	push   %r12
  4167cd:	push   %rbp
  4167ce:	push   %rbx
  4167cf:	mov    %rsi,%rbx
  4167d2:	mov    %edx,%ebp
  4167d4:	mov    0x288(%rdi),%r12
  4167db:	callq  4164e6 <LZWDecode>
  4167e0:	test   %eax,%eax
  4167e2:	je     4167f9 <LZWDecodePredRow+0x2e>
  4167e4:	movzwl 0x8(%r12),%edx
  4167ea:	mov    %ebp,%esi
  4167ec:	mov    %rbx,%rdi
  4167ef:	callq  *0x10(%r12)
  4167f4:	mov    $0x1,%eax
  4167f9:	pop    %rbx
  4167fa:	pop    %rbp
  4167fb:	pop    %r12
  4167fd:	retq   

00000000004167fe <LZWPreDecode>:
  4167fe:	push   %rbp
  4167ff:	push   %rbx
  416800:	sub    $0x8,%rsp
  416804:	mov    %rdi,%rbp
  416807:	mov    0x288(%rdi),%rbx
  41680e:	test   %rbx,%rbx
  416811:	je     4168a6 <LZWPreDecode+0xa8>
  416817:	andw   $0xfffe,0x4(%rbx)
  41681c:	movw   $0x9,0x6(%rbx)
  416822:	mov    $0xff,%eax
  416827:	mov    %al,0x274e(%rbx,%rax,1)
  41682e:	sub    $0x1,%rax
  416832:	cmp    $0xffffffffffffffff,%rax
  416836:	jne    416827 <LZWPreDecode+0x29>
  416838:	movl   $0x102,0x30(%rbx)
  41683f:	movq   $0x0,0x20(%rbx)
  416847:	mov    0x2a0(%rbp),%rax
  41684e:	lea    -0xb(,%rax,8),%rax
  416856:	mov    %rax,0x28(%rbx)
  41685a:	lea    0x374e(%rbx),%rax
  416861:	mov    %rax,0x3ae0(%rbx)
  416868:	movl   $0xffffffff,(%rbx)
  41686e:	movl   $0xffffffff,0x3ae8(%rbx)
  416878:	mov    0x298(%rbp),%rax
  41687f:	cmpb   $0x0,(%rax)
  416882:	jne    416959 <LZWPreDecode+0x15b>
  416888:	testb  $0x1,0x1(%rax)
  41688c:	je     416959 <LZWPreDecode+0x15b>
  416892:	testb  $0x2,0x4(%rbx)
  416896:	je     416941 <LZWPreDecode+0x143>
  41689c:	orw    $0x2,0x4(%rbx)
  4168a1:	jmpq   41695e <LZWPreDecode+0x160>
  4168a6:	mov    $0xc3c8,%edi
  4168ab:	mov    $0x0,%eax
  4168b0:	callq  401270 <malloc@plt>
  4168b5:	mov    %rax,%rbx
  4168b8:	mov    %rax,0x288(%rbp)
  4168bf:	test   %rax,%rax
  4168c2:	je     416926 <LZWPreDecode+0x128>
  4168c4:	movw   $0x0,0x4(%rax)
  4168ca:	movq   $0x0,0x10(%rax)
  4168d2:	movw   $0x0,0xa(%rax)
  4168d8:	mov    $0x415ae3,%ecx
  4168dd:	mov    $0x415a56,%edx
  4168e2:	mov    %rax,%rsi
  4168e5:	mov    %rbp,%rdi
  4168e8:	callq  416228 <LZWCheckPredictor>
  4168ed:	test   %eax,%eax
  4168ef:	je     416977 <LZWPreDecode+0x179>
  4168f5:	cmpq   $0x0,0x10(%rbx)
  4168fa:	je     41681c <LZWPreDecode+0x1e>
  416900:	movq   $0x4167cb,0x240(%rbp)
  41690b:	movq   $0x41677c,0x250(%rbp)
  416916:	movq   $0x41677c,0x260(%rbp)
  416921:	jmpq   41681c <LZWPreDecode+0x1e>
  416926:	mov    $0x41b13d,%esi
  41692b:	mov    $0x41b167,%edi
  416930:	mov    $0x0,%eax
  416935:	callq  412a93 <TIFFError>
  41693a:	mov    $0x0,%eax
  41693f:	jmp    416977 <LZWPreDecode+0x179>
  416941:	mov    $0x41b260,%esi
  416946:	mov    0x0(%rbp),%rdi
  41694a:	mov    $0x0,%eax
  41694f:	callq  413526 <TIFFWarning>
  416954:	jmpq   41689c <LZWPreDecode+0x9e>
  416959:	andw   $0xfffd,0x4(%rbx)
  41695e:	movl   $0x1fe,0x18(%rbx)
  416965:	mov    $0x1,%eax
  41696a:	testb  $0x2,0x4(%rbx)
  41696e:	je     416977 <LZWPreDecode+0x179>
  416970:	movl   $0x1ff,0x18(%rbx)
  416977:	add    $0x8,%rsp
  41697b:	pop    %rbx
  41697c:	pop    %rbp
  41697d:	retq   

000000000041697e <TIFFInitLZW>:
  41697e:	movq   $0x4167fe,0x228(%rdi)
  416989:	movq   $0x4164e6,0x240(%rdi)
  416994:	movq   $0x4164e6,0x250(%rdi)
  41699f:	movq   $0x4164e6,0x260(%rdi)
  4169aa:	movq   $0x4162d9,0x230(%rdi)
  4169b5:	movq   $0x4161eb,0x238(%rdi)
  4169c0:	movq   $0x415ea0,0x248(%rdi)
  4169cb:	movq   $0x415ea0,0x258(%rdi)
  4169d6:	movq   $0x415ea0,0x268(%rdi)
  4169e1:	movq   $0x415d60,0x280(%rdi)
  4169ec:	mov    $0x1,%eax
  4169f1:	retq   

00000000004169f2 <NeXTDecode>:
  4169f2:	push   %r15
  4169f4:	push   %r14
  4169f6:	push   %r13
  4169f8:	push   %r12
  4169fa:	push   %rbp
  4169fb:	push   %rbx
  4169fc:	sub    $0x28,%rsp
  416a00:	mov    %rdi,0x18(%rsp)
  416a05:	test   %edx,%edx
  416a07:	jle    416bc1 <NeXTDecode+0x1cf>
  416a0d:	mov    %rsi,%rbp
  416a10:	mov    %edx,%r12d
  416a13:	lea    -0x1(%rdx),%eax
  416a16:	lea    0x1(%rsi,%rax,1),%rdx
  416a1b:	mov    %rsi,%rax
  416a1e:	add    $0x1,%rax
  416a22:	movb   $0xff,-0x1(%rax)
  416a26:	cmp    %rdx,%rax
  416a29:	jne    416a1e <NeXTDecode+0x2c>
  416a2b:	mov    0x18(%rsp),%rax
  416a30:	mov    0x2a8(%rax),%rdi
  416a37:	mov    0x2b0(%rax),%ebx
  416a3d:	mov    0x290(%rax),%eax
  416a43:	mov    %eax,0xc(%rsp)
  416a47:	cltq   
  416a49:	mov    %rax,0x10(%rsp)
  416a4e:	jmp    416a91 <NeXTDecode+0x9f>
  416a50:	mov    0xc(%rsp),%r15d
  416a55:	cmp    %ebx,%r15d
  416a58:	jg     416b8f <NeXTDecode+0x19d>
  416a5e:	mov    %r15d,%edx
  416a61:	mov    %rbp,%rsi
  416a64:	mov    %r13,%rdi
  416a67:	mov    $0x0,%eax
  416a6c:	callq  4012d0 <bcopy@plt>
  416a71:	mov    0x10(%rsp),%rax
  416a76:	lea    0x0(%r13,%rax,1),%rdi
  416a7b:	sub    %r15d,%ebx
  416a7e:	sub    0xc(%rsp),%r12d
  416a83:	add    0x10(%rsp),%rbp
  416a88:	test   %r12d,%r12d
  416a8b:	jle    416bd3 <NeXTDecode+0x1e1>
  416a91:	lea    0x1(%rdi),%r13
  416a95:	movzbl (%rdi),%r8d
  416a99:	sub    $0x1,%ebx
  416a9c:	test   %r8b,%r8b
  416a9f:	je     416a50 <NeXTDecode+0x5e>
  416aa1:	cmp    $0x40,%r8b
  416aa5:	je     416ac5 <NeXTDecode+0xd3>
  416aa7:	movzbl %r8b,%r8d
  416aab:	mov    0x18(%rsp),%rax
  416ab0:	mov    0x30(%rax),%r14d
  416ab4:	mov    %rbp,%rcx
  416ab7:	mov    %r13,%rdi
  416aba:	mov    $0x0,%r9d
  416ac0:	jmpq   416b65 <NeXTDecode+0x173>
  416ac5:	movzbl 0x1(%rdi),%eax
  416ac9:	shl    $0x8,%eax
  416acc:	movzbl 0x2(%rdi),%edx
  416ad0:	add    %edx,%eax
  416ad2:	movzbl 0x3(%rdi),%edx
  416ad6:	shl    $0x8,%edx
  416ad9:	movzbl 0x4(%rdi),%ecx
  416add:	add    %ecx,%edx
  416adf:	lea    0x4(%rdx),%r14d
  416ae3:	cmp    %ebx,%r14d
  416ae6:	jg     416b8f <NeXTDecode+0x19d>
  416aec:	cltq   
  416aee:	lea    0x0(%rbp,%rax,1),%rsi
  416af3:	add    $0x5,%rdi
  416af7:	mov    $0x0,%eax
  416afc:	callq  4012d0 <bcopy@plt>
  416b01:	movslq %r14d,%rdi
  416b04:	add    %r13,%rdi
  416b07:	sub    %r14d,%ebx
  416b0a:	jmpq   416a7e <NeXTDecode+0x8c>
  416b0f:	test   %eax,%eax
  416b11:	jne    416b16 <NeXTDecode+0x124>
  416b13:	mov    %r11b,(%rcx)
  416b16:	mov    %edx,%eax
  416b18:	cmp    %eax,%esi
  416b1a:	je     416b49 <NeXTDecode+0x157>
  416b1c:	lea    0x1(%rax),%edx
  416b1f:	and    $0x3,%eax
  416b22:	cmp    $0x1,%eax
  416b25:	je     416b3f <NeXTDecode+0x14d>
  416b27:	cmp    $0x1,%eax
  416b2a:	jle    416b0f <NeXTDecode+0x11d>
  416b2c:	cmp    $0x2,%eax
  416b2f:	je     416b44 <NeXTDecode+0x152>
  416b31:	cmp    $0x3,%eax
  416b34:	jne    416b16 <NeXTDecode+0x124>
  416b36:	or     %r10b,(%rcx)
  416b39:	lea    0x1(%rcx),%rcx
  416b3d:	jmp    416b16 <NeXTDecode+0x124>
  416b3f:	or     %r13b,(%rcx)
  416b42:	jmp    416b16 <NeXTDecode+0x124>
  416b44:	or     %r15b,(%rcx)
  416b47:	jmp    416b16 <NeXTDecode+0x124>
  416b49:	add    %r8d,%r9d
  416b4c:	cmp    %r9d,%r14d
  416b4f:	jle    416a7e <NeXTDecode+0x8c>
  416b55:	test   %ebx,%ebx
  416b57:	je     416b8f <NeXTDecode+0x19d>
  416b59:	add    $0x1,%rdi
  416b5d:	movzbl -0x1(%rdi),%r8d
  416b62:	sub    $0x1,%ebx
  416b65:	mov    %r8d,%r10d
  416b68:	sar    $0x6,%r10d
  416b6c:	and    $0x3f,%r8d
  416b70:	lea    0x0(,%r10,4),%r15d
  416b78:	mov    %r10d,%r13d
  416b7b:	shl    $0x4,%r13d
  416b7f:	mov    %r10d,%r11d
  416b82:	shl    $0x6,%r11d
  416b86:	lea    (%r8,%r9,1),%esi
  416b8a:	mov    %r9d,%eax
  416b8d:	jmp    416b18 <NeXTDecode+0x126>
  416b8f:	mov    0x18(%rsp),%rax
  416b94:	mov    0x1f8(%rax),%rdx
  416b9b:	mov    $0x41b288,%esi
  416ba0:	mov    (%rax),%rdi
  416ba3:	mov    $0x0,%eax
  416ba8:	callq  412a93 <TIFFError>
  416bad:	mov    $0x0,%eax
  416bb2:	add    $0x28,%rsp
  416bb6:	pop    %rbx
  416bb7:	pop    %rbp
  416bb8:	pop    %r12
  416bba:	pop    %r13
  416bbc:	pop    %r14
  416bbe:	pop    %r15
  416bc0:	retq   
  416bc1:	mov    0x18(%rsp),%rax
  416bc6:	mov    0x2a8(%rax),%rdi
  416bcd:	mov    0x2b0(%rax),%ebx
  416bd3:	mov    0x18(%rsp),%rax
  416bd8:	mov    %rdi,0x2a8(%rax)
  416bdf:	movslq %ebx,%rbx
  416be2:	mov    %rbx,0x2b0(%rax)
  416be9:	mov    $0x1,%eax
  416bee:	jmp    416bb2 <NeXTDecode+0x1c0>

0000000000416bf0 <TIFFInitNeXT>:
  416bf0:	movq   $0x4169f2,0x240(%rdi)
  416bfb:	movq   $0x4169f2,0x250(%rdi)
  416c06:	movq   $0x4169f2,0x260(%rdi)
  416c11:	mov    $0x1,%eax
  416c16:	retq   

0000000000416c17 <PackBitsEncode>:
  416c17:	push   %r15
  416c19:	push   %r14
  416c1b:	push   %r13
  416c1d:	push   %r12
  416c1f:	push   %rbp
  416c20:	push   %rbx
  416c21:	sub    $0x28,%rsp
  416c25:	mov    %rdi,%r12
  416c28:	mov    %rsi,(%rsp)
  416c2c:	mov    %edx,%r14d
  416c2f:	mov    0x2a8(%rdi),%rax
  416c36:	mov    0x2a0(%rdi),%rdx
  416c3d:	add    0x298(%rdi),%rdx
  416c44:	mov    %rdx,0x8(%rsp)
  416c49:	test   %r14d,%r14d
  416c4c:	jle    416f0f <PackBitsEncode+0x2f8>
  416c52:	mov    $0x0,%ebp
  416c57:	mov    $0x0,%r15d
  416c5d:	movl   $0x3,0x1c(%rsp)
  416c65:	jmpq   416d93 <PackBitsEncode+0x17c>
  416c6a:	mov    %ecx,%r14d
  416c6d:	mov    %rdx,(%rsp)
  416c71:	mov    $0x1,%ebx
  416c76:	jmpq   416d26 <PackBitsEncode+0x10f>
  416c7b:	mov    %ecx,%r14d
  416c7e:	mov    %rdx,(%rsp)
  416c82:	mov    $0x1,%ebx
  416c87:	jmpq   416d26 <PackBitsEncode+0x10f>
  416c8c:	sub    %r15,%rax
  416c8f:	mov    %rax,0x10(%rsp)
  416c94:	mov    %r15,%rax
  416c97:	sub    0x2a8(%r12),%rax
  416c9f:	add    %rax,0x2b0(%r12)
  416ca7:	mov    %r12,%rdi
  416caa:	mov    $0x0,%eax
  416caf:	callq  41425a <TIFFFlushData1>
  416cb4:	test   %eax,%eax
  416cb6:	je     416f3e <PackBitsEncode+0x327>
  416cbc:	mov    0x2a8(%r12),%rax
  416cc4:	mov    0x10(%rsp),%rsi
  416cc9:	lea    -0x1(%rsi),%edi
  416ccc:	test   %esi,%esi
  416cce:	jle    416cf4 <PackBitsEncode+0xdd>
  416cd0:	lea    -0x1(%rsi),%esi
  416cd3:	add    $0x1,%rsi
  416cd7:	mov    $0x0,%edx
  416cdc:	movzbl (%r15,%rdx,1),%ecx
  416ce1:	mov    %cl,(%rax,%rdx,1)
  416ce4:	add    $0x1,%rdx
  416ce8:	cmp    %rdx,%rsi
  416ceb:	jne    416cdc <PackBitsEncode+0xc5>
  416ced:	mov    %edi,%edi
  416cef:	lea    0x1(%rax,%rdi,1),%rax
  416cf4:	mov    0x2a8(%r12),%r15
  416cfc:	jmp    416d6a <PackBitsEncode+0x153>
  416cfe:	cmp    $0x1,%ebx
  416d01:	jle    416e07 <PackBitsEncode+0x1f0>
  416d07:	cmp    $0x80,%ebx
  416d0d:	jle    416def <PackBitsEncode+0x1d8>
  416d13:	movb   $0x81,(%rax)
  416d16:	mov    %r13b,0x1(%rax)
  416d1a:	add    $0xffffff80,%ebx
  416d1d:	lea    0x2(%rax),%rax
  416d21:	mov    $0x2,%ebp
  416d26:	lea    0x2(%rax),%rdx
  416d2a:	cmp    %rdx,0x8(%rsp)
  416d2f:	ja     416d6a <PackBitsEncode+0x153>
  416d31:	test   $0xfffffffd,%ebp
  416d37:	jne    416c8c <PackBitsEncode+0x75>
  416d3d:	sub    0x2a8(%r12),%rax
  416d45:	add    %rax,0x2b0(%r12)
  416d4d:	mov    %r12,%rdi
  416d50:	mov    $0x0,%eax
  416d55:	callq  41425a <TIFFFlushData1>
  416d5a:	test   %eax,%eax
  416d5c:	je     416f45 <PackBitsEncode+0x32e>
  416d62:	mov    0x2a8(%r12),%rax
  416d6a:	cmp    $0x1,%ebp
  416d6d:	je     416e1f <PackBitsEncode+0x208>
  416d73:	cmp    $0x1,%ebp
  416d76:	jb     416cfe <PackBitsEncode+0xe7>
  416d78:	cmp    $0x2,%ebp
  416d7b:	je     416e7f <PackBitsEncode+0x268>
  416d81:	cmp    $0x3,%ebp
  416d84:	je     416ecd <PackBitsEncode+0x2b6>
  416d8a:	test   %r14d,%r14d
  416d8d:	jle    416f0f <PackBitsEncode+0x2f8>
  416d93:	mov    (%rsp),%rdi
  416d97:	lea    0x1(%rdi),%rdx
  416d9b:	movzbl (%rdi),%r13d
  416d9f:	lea    -0x1(%r14),%ecx
  416da3:	test   %ecx,%ecx
  416da5:	jle    416c6a <PackBitsEncode+0x53>
  416dab:	cmp    0x1(%rdi),%r13b
  416daf:	jne    416c7b <PackBitsEncode+0x64>
  416db5:	mov    %r14d,%ecx
  416db8:	lea    -0x2(%r14),%esi
  416dbc:	lea    0x2(%rdi,%rsi,1),%rbx
  416dc1:	mov    %rbx,(%rsp)
  416dc5:	mov    $0x1,%ebx
  416dca:	add    $0x1,%ebx
  416dcd:	mov    %ecx,%r14d
  416dd0:	sub    %ebx,%r14d
  416dd3:	add    $0x1,%rdx
  416dd7:	cmp    (%rsp),%rdx
  416ddb:	je     416d26 <PackBitsEncode+0x10f>
  416de1:	cmp    (%rdx),%r13b
  416de4:	je     416dca <PackBitsEncode+0x1b3>
  416de6:	mov    %rdx,(%rsp)
  416dea:	jmpq   416d26 <PackBitsEncode+0x10f>
  416def:	mov    $0x1,%edx
  416df4:	sub    %ebx,%edx
  416df6:	mov    %dl,(%rax)
  416df8:	mov    %r13b,0x1(%rax)
  416dfc:	lea    0x2(%rax),%rax
  416e00:	mov    $0x2,%ebp
  416e05:	jmp    416d8a <PackBitsEncode+0x173>
  416e07:	movb   $0x0,(%rax)
  416e0a:	mov    %r13b,0x1(%rax)
  416e0e:	mov    %rax,%r15
  416e11:	lea    0x2(%rax),%rax
  416e15:	mov    $0x1,%ebp
  416e1a:	jmpq   416d8a <PackBitsEncode+0x173>
  416e1f:	cmp    $0x1,%ebx
  416e22:	jle    416e5e <PackBitsEncode+0x247>
  416e24:	cmp    $0x80,%ebx
  416e2a:	jle    416e43 <PackBitsEncode+0x22c>
  416e2c:	movb   $0x81,(%rax)
  416e2f:	mov    %r13b,0x1(%rax)
  416e33:	add    $0xffffff80,%ebx
  416e36:	lea    0x2(%rax),%rax
  416e3a:	mov    0x1c(%rsp),%ebp
  416e3e:	jmpq   416d26 <PackBitsEncode+0x10f>
  416e43:	mov    $0x1,%edx
  416e48:	sub    %ebx,%edx
  416e4a:	mov    %dl,(%rax)
  416e4c:	mov    %r13b,0x1(%rax)
  416e50:	lea    0x2(%rax),%rax
  416e54:	mov    $0x3,%ebp
  416e59:	jmpq   416d8a <PackBitsEncode+0x173>
  416e5e:	movzbl (%r15),%ecx
  416e62:	lea    0x1(%rcx),%edx
  416e65:	mov    %dl,(%r15)
  416e68:	cmp    $0x7f,%dl
  416e6b:	setne  %bpl
  416e6f:	movzbl %bpl,%ebp
  416e73:	mov    %r13b,(%rax)
  416e76:	lea    0x1(%rax),%rax
  416e7a:	jmpq   416d8a <PackBitsEncode+0x173>
  416e7f:	cmp    $0x1,%ebx
  416e82:	jle    416eb5 <PackBitsEncode+0x29e>
  416e84:	cmp    $0x80,%ebx
  416e8a:	jle    416e9f <PackBitsEncode+0x288>
  416e8c:	movb   $0x81,(%rax)
  416e8f:	mov    %r13b,0x1(%rax)
  416e93:	add    $0xffffff80,%ebx
  416e96:	lea    0x2(%rax),%rax
  416e9a:	jmpq   416d26 <PackBitsEncode+0x10f>
  416e9f:	mov    $0x1,%edx
  416ea4:	sub    %ebx,%edx
  416ea6:	mov    %dl,(%rax)
  416ea8:	mov    %r13b,0x1(%rax)
  416eac:	lea    0x2(%rax),%rax
  416eb0:	jmpq   416d8a <PackBitsEncode+0x173>
  416eb5:	movb   $0x0,(%rax)
  416eb8:	mov    %r13b,0x1(%rax)
  416ebc:	mov    %rax,%r15
  416ebf:	lea    0x2(%rax),%rax
  416ec3:	mov    $0x1,%ebp
  416ec8:	jmpq   416d8a <PackBitsEncode+0x173>
  416ecd:	mov    $0x2,%ebp
  416ed2:	cmp    $0x1,%ebx
  416ed5:	jne    416d26 <PackBitsEncode+0x10f>
  416edb:	cmpb   $0xff,-0x2(%rax)
  416edf:	jne    416d26 <PackBitsEncode+0x10f>
  416ee5:	movzbl (%r15),%edx
  416ee9:	cmp    $0x7d,%dl
  416eec:	jg     416d26 <PackBitsEncode+0x10f>
  416ef2:	add    $0x2,%edx
  416ef5:	mov    %dl,(%r15)
  416ef8:	cmp    $0x7f,%dl
  416efb:	setne  %bpl
  416eff:	movzbl %bpl,%ebp
  416f03:	movzbl -0x1(%rax),%edx
  416f07:	mov    %dl,-0x2(%rax)
  416f0a:	jmpq   416d26 <PackBitsEncode+0x10f>
  416f0f:	mov    %rax,%rdx
  416f12:	sub    0x2a8(%r12),%rdx
  416f1a:	add    %rdx,0x2b0(%r12)
  416f22:	mov    %rax,0x2a8(%r12)
  416f2a:	mov    $0x1,%eax
  416f2f:	add    $0x28,%rsp
  416f33:	pop    %rbx
  416f34:	pop    %rbp
  416f35:	pop    %r12
  416f37:	pop    %r13
  416f39:	pop    %r14
  416f3b:	pop    %r15
  416f3d:	retq   
  416f3e:	mov    $0xffffffff,%eax
  416f43:	jmp    416f2f <PackBitsEncode+0x318>
  416f45:	mov    $0xffffffff,%eax
  416f4a:	jmp    416f2f <PackBitsEncode+0x318>

0000000000416f4c <PackBitsEncodeChunk>:
  416f4c:	push   %r15
  416f4e:	push   %r14
  416f50:	push   %r13
  416f52:	push   %r12
  416f54:	push   %rbp
  416f55:	push   %rbx
  416f56:	sub    $0x8,%rsp
  416f5a:	mov    0x288(%rdi),%rax
  416f61:	test   %eax,%eax
  416f63:	jle    416fa5 <PackBitsEncodeChunk+0x59>
  416f65:	mov    %rdi,%r13
  416f68:	mov    %rsi,%rbp
  416f6b:	mov    %edx,%ebx
  416f6d:	mov    %ecx,%r14d
  416f70:	mov    %eax,%r12d
  416f73:	movslq %eax,%r15
  416f76:	mov    $0x1,%eax
  416f7b:	test   %edx,%edx
  416f7d:	jle    416fc3 <PackBitsEncodeChunk+0x77>
  416f7f:	mov    %r14d,%ecx
  416f82:	mov    %r12d,%edx
  416f85:	mov    %rbp,%rsi
  416f88:	mov    %r13,%rdi
  416f8b:	callq  416c17 <PackBitsEncode>
  416f90:	test   %eax,%eax
  416f92:	js     416fbe <PackBitsEncodeChunk+0x72>
  416f94:	add    %r15,%rbp
  416f97:	sub    %r12d,%ebx
  416f9a:	test   %ebx,%ebx
  416f9c:	jg     416f7f <PackBitsEncodeChunk+0x33>
  416f9e:	mov    $0x1,%eax
  416fa3:	jmp    416fc3 <PackBitsEncodeChunk+0x77>
  416fa5:	mov    $0x41b300,%ecx
  416faa:	mov    $0x5c,%edx
  416faf:	mov    $0x41b2b4,%esi
  416fb4:	mov    $0x41b2c3,%edi
  416fb9:	callq  4011b0 <__assert_fail@plt>
  416fbe:	mov    $0xffffffff,%eax
  416fc3:	add    $0x8,%rsp
  416fc7:	pop    %rbx
  416fc8:	pop    %rbp
  416fc9:	pop    %r12
  416fcb:	pop    %r13
  416fcd:	pop    %r14
  416fcf:	pop    %r15
  416fd1:	retq   

0000000000416fd2 <PackBitsPreEncode>:
  416fd2:	push   %rbx
  416fd3:	mov    %rdi,%rbx
  416fd6:	testb  $0x80,0xe(%rdi)
  416fda:	jne    416ff1 <PackBitsPreEncode+0x1f>
  416fdc:	callq  412fcd <TIFFScanlineSize>
  416fe1:	cltq   
  416fe3:	mov    %rax,0x288(%rbx)
  416fea:	mov    $0x1,%eax
  416fef:	pop    %rbx
  416ff0:	retq   
  416ff1:	callq  4133ab <TIFFTileRowSize>
  416ff6:	mov    %rax,0x288(%rbx)
  416ffd:	jmp    416fea <PackBitsPreEncode+0x18>

0000000000416fff <PackBitsDecode>:
  416fff:	push   %r15
  417001:	push   %r14
  417003:	push   %r13
  417005:	push   %r12
  417007:	push   %rbp
  417008:	push   %rbx
  417009:	sub    $0x8,%rsp
  41700d:	mov    %rdi,%r15
  417010:	mov    %rsi,%r13
  417013:	mov    %edx,%r12d
  417016:	mov    0x2a8(%rdi),%rax
  41701d:	mov    0x2b0(%rdi),%ebp
  417023:	jmp    417048 <PackBitsDecode+0x49>
  417025:	add    $0x1,%ebx
  417028:	mov    %ebx,%edx
  41702a:	mov    %r13,%rsi
  41702d:	mov    %r14,%rdi
  417030:	mov    $0x0,%eax
  417035:	callq  4012d0 <bcopy@plt>
  41703a:	movslq %ebx,%rax
  41703d:	add    %rax,%r13
  417040:	sub    %ebx,%r12d
  417043:	add    %r14,%rax
  417046:	sub    %ebx,%ebp
  417048:	test   %ebp,%ebp
  41704a:	jle    4170b3 <PackBitsDecode+0xb4>
  41704c:	test   %r12d,%r12d
  41704f:	jle    4170b3 <PackBitsDecode+0xb4>
  417051:	lea    0x1(%rax),%r14
  417055:	movsbl (%rax),%ebx
  417058:	test   %ebx,%ebx
  41705a:	jns    417025 <PackBitsDecode+0x26>
  41705c:	sub    $0x1,%ebp
  41705f:	cmp    $0xffffff80,%ebx
  417062:	je     4170a9 <PackBitsDecode+0xaa>
  417064:	mov    $0x1,%edx
  417069:	sub    %ebx,%edx
  41706b:	sub    %edx,%r12d
  41706e:	lea    0x2(%rax),%rdi
  417072:	movzbl 0x1(%rax),%esi
  417076:	neg    %ebx
  417078:	test   %edx,%edx
  41707a:	jle    4170ae <PackBitsDecode+0xaf>
  41707c:	mov    %ebx,%edx
  41707e:	mov    %r13,%rax
  417081:	add    $0x1,%rax
  417085:	mov    %sil,-0x1(%rax)
  417089:	sub    $0x1,%edx
  41708c:	lea    0x1(%rdx),%ecx
  41708f:	test   %ecx,%ecx
  417091:	jg     417081 <PackBitsDecode+0x82>
  417093:	test   %ebx,%ebx
  417095:	mov    $0x0,%eax
  41709a:	cmovs  %eax,%ebx
  41709d:	mov    %ebx,%ebx
  41709f:	lea    0x1(%r13,%rbx,1),%r13
  4170a4:	mov    %rdi,%rax
  4170a7:	jmp    417048 <PackBitsDecode+0x49>
  4170a9:	mov    %r14,%rax
  4170ac:	jmp    417048 <PackBitsDecode+0x49>
  4170ae:	mov    %rdi,%rax
  4170b1:	jmp    417048 <PackBitsDecode+0x49>
  4170b3:	mov    %rax,0x2a8(%r15)
  4170ba:	movslq %ebp,%rbp
  4170bd:	mov    %rbp,0x2b0(%r15)
  4170c4:	mov    $0x1,%eax
  4170c9:	test   %r12d,%r12d
  4170cc:	jle    4170ec <PackBitsDecode+0xed>
  4170ce:	mov    0x1f8(%r15),%rdx
  4170d5:	mov    $0x41b2d0,%esi
  4170da:	mov    (%r15),%rdi
  4170dd:	mov    $0x0,%eax
  4170e2:	callq  412a93 <TIFFError>
  4170e7:	mov    $0x0,%eax
  4170ec:	add    $0x8,%rsp
  4170f0:	pop    %rbx
  4170f1:	pop    %rbp
  4170f2:	pop    %r12
  4170f4:	pop    %r13
  4170f6:	pop    %r14
  4170f8:	pop    %r15
  4170fa:	retq   

00000000004170fb <TIFFInitPackBits>:
  4170fb:	movq   $0x416fff,0x240(%rdi)
  417106:	movq   $0x416fff,0x250(%rdi)
  417111:	movq   $0x416fff,0x260(%rdi)
  41711c:	movq   $0x416fd2,0x230(%rdi)
  417127:	movq   $0x416c17,0x248(%rdi)
  417132:	movq   $0x416f4c,0x258(%rdi)
  41713d:	movq   $0x416f4c,0x268(%rdi)
  417148:	mov    $0x1,%eax
  41714d:	retq   

000000000041714e <ThunderDecodeRow>:
  41714e:	test   %edx,%edx
  417150:	jle    4173f0 <ThunderDecodeRow+0x2a2>
  417156:	push   %r14
  417158:	push   %r13
  41715a:	push   %r12
  41715c:	push   %rbp
  41715d:	push   %rbx
  41715e:	mov    $0x0,%r13d
  417164:	jmpq   417407 <ThunderDecodeRow+0x2b9>
  417169:	test   %r14b,%r14b
  41716c:	jne    4171c4 <ThunderDecodeRow+0x76>
  41716e:	test   $0x1,%r8b
  417172:	je     41722b <ThunderDecodeRow+0xdd>
  417178:	or     (%rax),%r11b
  41717b:	mov    %r11b,(%rax)
  41717e:	add    $0x1,%rax
  417182:	movzbl %r11b,%r11d
  417186:	add    $0x1,%r8d
  41718a:	sub    $0x1,%r10d
  41718e:	add    %r10d,%r8d
  417191:	test   %r10d,%r10d
  417194:	jle    4171ba <ThunderDecodeRow+0x6c>
  417196:	lea    -0x1(%r10),%r14d
  41719a:	shr    %r14d
  41719d:	mov    %r14d,%ecx
  4171a0:	lea    0x1(%rax,%rcx,1),%rcx
  4171a5:	add    $0x1,%rax
  4171a9:	mov    %r11b,-0x1(%rax)
  4171ad:	cmp    %rcx,%rax
  4171b0:	jne    4171a5 <ThunderDecodeRow+0x57>
  4171b2:	neg    %r14d
  4171b5:	lea    -0x2(%r10,%r14,2),%r10d
  4171ba:	cmp    $0xffffffff,%r10d
  4171be:	je     417239 <ThunderDecodeRow+0xeb>
  4171c0:	and    $0xf,%r11d
  4171c4:	test   %ebx,%ebx
  4171c6:	jle    4173a2 <ThunderDecodeRow+0x254>
  4171cc:	cmp    %r8d,%r9d
  4171cf:	jle    4173a2 <ThunderDecodeRow+0x254>
  4171d5:	add    $0x1,%rbp
  4171d9:	movzbl -0x1(%rbp),%ecx
  4171dd:	movzbl %cl,%r10d
  4171e1:	sub    $0x1,%ebx
  4171e4:	mov    %ecx,%r14d
  4171e7:	and    $0xffffffc0,%r14d
  4171eb:	cmp    $0x40,%r14b
  4171ef:	je     417246 <ThunderDecodeRow+0xf8>
  4171f1:	cmp    $0x40,%r14b
  4171f5:	jbe    417169 <ThunderDecodeRow+0x1b>
  4171fb:	cmp    $0x80,%r14b
  4171ff:	je     41730f <ThunderDecodeRow+0x1c1>
  417205:	cmp    $0xc0,%r14b
  417209:	jne    4171c4 <ThunderDecodeRow+0x76>
  41720b:	and    $0xf,%ecx
  41720e:	movzbl %cl,%r11d
  417212:	lea    0x1(%r8),%r10d
  417216:	test   $0x1,%r8b
  41721a:	je     417395 <ThunderDecodeRow+0x247>
  417220:	or     %cl,(%rax)
  417222:	mov    %r10d,%r8d
  417225:	lea    0x1(%rax),%rax
  417229:	jmp    4171c4 <ThunderDecodeRow+0x76>
  41722b:	mov    %r11d,%ecx
  41722e:	shl    $0x4,%ecx
  417231:	or     %ecx,%r11d
  417234:	jmpq   41718e <ThunderDecodeRow+0x40>
  417239:	andb   $0xf0,-0x1(%rax)
  41723d:	lea    -0x1(%rax),%rax
  417241:	jmpq   4171c0 <ThunderDecodeRow+0x72>
  417246:	mov    %r10d,%r14d
  417249:	sar    $0x4,%r14d
  41724d:	and    $0x3,%r14d
  417251:	cmp    $0x2,%r14d
  417255:	je     41727a <ThunderDecodeRow+0x12c>
  417257:	movslq %r14d,%r14
  41725a:	add    0x41b380(,%r14,4),%r11d
  417262:	and    $0xf,%r11d
  417266:	lea    0x1(%r8),%r14d
  41726a:	test   $0x1,%r8b
  41726e:	je     4172df <ThunderDecodeRow+0x191>
  417270:	or     %r11b,(%rax)
  417273:	mov    %r14d,%r8d
  417276:	lea    0x1(%rax),%rax
  41727a:	sar    $0x2,%r10d
  41727e:	and    $0x3,%r10d
  417282:	cmp    $0x2,%r10d
  417286:	je     4172ab <ThunderDecodeRow+0x15d>
  417288:	movslq %r10d,%r10
  41728b:	add    0x41b380(,%r10,4),%r11d
  417293:	and    $0xf,%r11d
  417297:	lea    0x1(%r8),%r10d
  41729b:	test   $0x1,%r8b
  41729f:	je     4172ee <ThunderDecodeRow+0x1a0>
  4172a1:	or     %r11b,(%rax)
  4172a4:	mov    %r10d,%r8d
  4172a7:	lea    0x1(%rax),%rax
  4172ab:	and    $0x3,%ecx
  4172ae:	cmp    $0x2,%ecx
  4172b1:	je     4171c4 <ThunderDecodeRow+0x76>
  4172b7:	movslq %ecx,%rcx
  4172ba:	add    0x41b380(,%rcx,4),%r11d
  4172c2:	and    $0xf,%r11d
  4172c6:	lea    0x1(%r8),%ecx
  4172ca:	test   $0x1,%r8b
  4172ce:	je     4172fd <ThunderDecodeRow+0x1af>
  4172d0:	or     %r11b,(%rax)
  4172d3:	mov    %ecx,%r8d
  4172d6:	lea    0x1(%rax),%rax
  4172da:	jmpq   4171c4 <ThunderDecodeRow+0x76>
  4172df:	mov    %r11d,%r8d
  4172e2:	shl    $0x4,%r8d
  4172e6:	mov    %r8b,(%rax)
  4172e9:	mov    %r14d,%r8d
  4172ec:	jmp    41727a <ThunderDecodeRow+0x12c>
  4172ee:	mov    %r11d,%r8d
  4172f1:	shl    $0x4,%r8d
  4172f5:	mov    %r8b,(%rax)
  4172f8:	mov    %r10d,%r8d
  4172fb:	jmp    4172ab <ThunderDecodeRow+0x15d>
  4172fd:	mov    %r11d,%r8d
  417300:	shl    $0x4,%r8d
  417304:	mov    %r8b,(%rax)
  417307:	mov    %ecx,%r8d
  41730a:	jmpq   4171c4 <ThunderDecodeRow+0x76>
  41730f:	sar    $0x3,%r10d
  417313:	and    $0x7,%r10d
  417317:	cmp    $0x4,%r10d
  41731b:	je     417340 <ThunderDecodeRow+0x1f2>
  41731d:	movslq %r10d,%r10
  417320:	add    0x41b360(,%r10,4),%r11d
  417328:	and    $0xf,%r11d
  41732c:	lea    0x1(%r8),%r10d
  417330:	test   $0x1,%r8b
  417334:	je     417374 <ThunderDecodeRow+0x226>
  417336:	or     %r11b,(%rax)
  417339:	mov    %r10d,%r8d
  41733c:	lea    0x1(%rax),%rax
  417340:	and    $0x7,%ecx
  417343:	cmp    $0x4,%ecx
  417346:	je     4171c4 <ThunderDecodeRow+0x76>
  41734c:	movslq %ecx,%rcx
  41734f:	add    0x41b360(,%rcx,4),%r11d
  417357:	and    $0xf,%r11d
  41735b:	lea    0x1(%r8),%ecx
  41735f:	test   $0x1,%r8b
  417363:	je     417383 <ThunderDecodeRow+0x235>
  417365:	or     %r11b,(%rax)
  417368:	mov    %ecx,%r8d
  41736b:	lea    0x1(%rax),%rax
  41736f:	jmpq   4171c4 <ThunderDecodeRow+0x76>
  417374:	mov    %r11d,%r8d
  417377:	shl    $0x4,%r8d
  41737b:	mov    %r8b,(%rax)
  41737e:	mov    %r10d,%r8d
  417381:	jmp    417340 <ThunderDecodeRow+0x1f2>
  417383:	mov    %r11d,%r8d
  417386:	shl    $0x4,%r8d
  41738a:	mov    %r8b,(%rax)
  41738d:	mov    %ecx,%r8d
  417390:	jmpq   4171c4 <ThunderDecodeRow+0x76>
  417395:	shl    $0x4,%ecx
  417398:	mov    %cl,(%rax)
  41739a:	mov    %r10d,%r8d
  41739d:	jmpq   4171c4 <ThunderDecodeRow+0x76>
  4173a2:	mov    %rbp,0x2a8(%rdi)
  4173a9:	movslq %ebx,%rbx
  4173ac:	mov    %rbx,0x2b0(%rdi)
  4173b3:	cmp    %r8d,%r12d
  4173b6:	je     4173f6 <ThunderDecodeRow+0x2a8>
  4173b8:	mov    0x1f8(%rdi),%rcx
  4173bf:	cmp    %r8d,%r9d
  4173c2:	mov    $0x41b314,%edx
  4173c7:	mov    $0x41b31f,%eax
  4173cc:	cmovle %rax,%rdx
  4173d0:	mov    $0x41b328,%esi
  4173d5:	mov    (%rdi),%rdi
  4173d8:	mov    $0x0,%eax
  4173dd:	callq  412a93 <TIFFError>
  4173e2:	mov    $0x0,%eax
  4173e7:	pop    %rbx
  4173e8:	pop    %rbp
  4173e9:	pop    %r12
  4173eb:	pop    %r13
  4173ed:	pop    %r14
  4173ef:	retq   
  4173f0:	mov    $0x1,%eax
  4173f5:	retq   
  4173f6:	mov    0x290(%rdi),%eax
  4173fc:	sub    %eax,%edx
  4173fe:	cltq   
  417400:	add    %rax,%rsi
  417403:	test   %edx,%edx
  417405:	jle    41742c <ThunderDecodeRow+0x2de>
  417407:	mov    0x30(%rdi),%r12
  41740b:	mov    %r12d,%r9d
  41740e:	mov    0x2a8(%rdi),%rbp
  417415:	mov    0x2b0(%rdi),%ebx
  41741b:	mov    %rsi,%rax
  41741e:	mov    $0x0,%r8d
  417424:	mov    %r13d,%r11d
  417427:	jmpq   4171c4 <ThunderDecodeRow+0x76>
  41742c:	mov    $0x1,%eax
  417431:	jmp    4173e7 <ThunderDecodeRow+0x299>

0000000000417433 <TIFFInitThunderScan>:
  417433:	movq   $0x41714e,0x240(%rdi)
  41743e:	movq   $0x41714e,0x250(%rdi)
  417449:	mov    $0x1,%eax
  41744e:	retq   

000000000041744f <skiptoeol>:
  41744f:	mov    0x288(%rdi),%r9
  417456:	movswl 0x2(%r9),%edx
  41745b:	movswl (%r9),%ecx
  41745f:	test   %edx,%edx
  417461:	mov    $0x8,%eax
  417466:	cmove  %eax,%edx
  417469:	jmpq   417600 <skiptoeol+0x1b1>
  41746e:	mov    $0x0,%eax
  417473:	add    %eax,%eax
  417475:	mov    %ecx,%r8d
  417478:	and    $0x40,%r8d
  41747c:	mov    %eax,%edx
  41747e:	or     $0x1,%edx
  417481:	test   %r8d,%r8d
  417484:	cmovne %edx,%eax
  417487:	add    $0x1,%esi
  41748a:	mov    $0x2,%edx
  41748f:	test   %eax,%eax
  417491:	jg     4175e9 <skiptoeol+0x19a>
  417497:	jmp    41749e <skiptoeol+0x4f>
  417499:	mov    $0x0,%eax
  41749e:	add    %eax,%eax
  4174a0:	mov    %ecx,%r8d
  4174a3:	and    $0x20,%r8d
  4174a7:	mov    %eax,%edx
  4174a9:	or     $0x1,%edx
  4174ac:	test   %r8d,%r8d
  4174af:	cmovne %edx,%eax
  4174b2:	add    $0x1,%esi
  4174b5:	mov    $0x3,%edx
  4174ba:	test   %eax,%eax
  4174bc:	jg     4175e9 <skiptoeol+0x19a>
  4174c2:	jmp    4174c9 <skiptoeol+0x7a>
  4174c4:	mov    $0x0,%eax
  4174c9:	add    %eax,%eax
  4174cb:	mov    %ecx,%r8d
  4174ce:	and    $0x10,%r8d
  4174d2:	mov    %eax,%edx
  4174d4:	or     $0x1,%edx
  4174d7:	test   %r8d,%r8d
  4174da:	cmovne %edx,%eax
  4174dd:	add    $0x1,%esi
  4174e0:	mov    $0x4,%edx
  4174e5:	test   %eax,%eax
  4174e7:	jg     4175e9 <skiptoeol+0x19a>
  4174ed:	jmp    4174f4 <skiptoeol+0xa5>
  4174ef:	mov    $0x0,%eax
  4174f4:	add    %eax,%eax
  4174f6:	mov    %ecx,%r8d
  4174f9:	and    $0x8,%r8d
  4174fd:	mov    %eax,%edx
  4174ff:	or     $0x1,%edx
  417502:	test   %r8d,%r8d
  417505:	cmovne %edx,%eax
  417508:	add    $0x1,%esi
  41750b:	mov    $0x5,%edx
  417510:	test   %eax,%eax
  417512:	jg     4175e9 <skiptoeol+0x19a>
  417518:	jmp    41751f <skiptoeol+0xd0>
  41751a:	mov    $0x0,%eax
  41751f:	add    %eax,%eax
  417521:	mov    %ecx,%r8d
  417524:	and    $0x4,%r8d
  417528:	mov    %eax,%edx
  41752a:	or     $0x1,%edx
  41752d:	test   %r8d,%r8d
  417530:	cmovne %edx,%eax
  417533:	add    $0x1,%esi
  417536:	mov    $0x6,%edx
  41753b:	test   %eax,%eax
  41753d:	jg     4175e9 <skiptoeol+0x19a>
  417543:	jmp    41754a <skiptoeol+0xfb>
  417545:	mov    $0x0,%eax
  41754a:	add    %eax,%eax
  41754c:	mov    %ecx,%r8d
  41754f:	and    $0x2,%r8d
  417553:	mov    %eax,%edx
  417555:	or     $0x1,%edx
  417558:	test   %r8d,%r8d
  41755b:	cmovne %edx,%eax
  41755e:	add    $0x1,%esi
  417561:	mov    $0x7,%edx
  417566:	test   %eax,%eax
  417568:	jg     4175e9 <skiptoeol+0x19a>
  41756a:	jmp    417571 <skiptoeol+0x122>
  41756c:	mov    $0x0,%eax
  417571:	add    %eax,%eax
  417573:	mov    %ecx,%r8d
  417576:	and    $0x1,%r8d
  41757a:	add    $0x1,%esi
  41757d:	mov    $0x8,%edx
  417582:	or     %r8d,%eax
  417585:	jg     4175e9 <skiptoeol+0x19a>
  417587:	mov    0x2b0(%rdi),%rdx
  41758e:	test   %rdx,%rdx
  417591:	jle    41762c <skiptoeol+0x1dd>
  417597:	sub    $0x1,%rdx
  41759b:	mov    %rdx,0x2b0(%rdi)
  4175a2:	mov    0x20(%r9),%rcx
  4175a6:	mov    0x2a8(%rdi),%rdx
  4175ad:	lea    0x1(%rdx),%r8
  4175b1:	mov    %r8,0x2a8(%rdi)
  4175b8:	movzbl (%rdx),%edx
  4175bb:	movzbl (%rcx,%rdx,1),%ecx
  4175bf:	mov    %eax,%edx
  4175c1:	lea    (%rdx,%rdx,1),%eax
  4175c4:	mov    %ecx,%r8d
  4175c7:	and    $0x80,%r8d
  4175ce:	mov    %eax,%edx
  4175d0:	or     $0x1,%edx
  4175d3:	test   %r8d,%r8d
  4175d6:	cmovne %edx,%eax
  4175d9:	add    $0x1,%esi
  4175dc:	mov    $0x1,%edx
  4175e1:	test   %eax,%eax
  4175e3:	jle    417473 <skiptoeol+0x24>
  4175e9:	cmp    $0xb,%esi
  4175ec:	setg   %r8b
  4175f0:	cmp    $0x1,%eax
  4175f3:	sete   %al
  4175f6:	mov    $0x0,%esi
  4175fb:	test   %al,%r8b
  4175fe:	jne    417618 <skiptoeol+0x1c9>
  417600:	cmp    $0x7,%edx
  417603:	ja     41760e <skiptoeol+0x1bf>
  417605:	mov    %edx,%eax
  417607:	jmpq   *0x41b3a0(,%rax,8)
  41760e:	mov    $0x0,%eax
  417613:	jmpq   417587 <skiptoeol+0x138>
  417618:	cmp    $0x8,%edx
  41761b:	mov    $0x0,%eax
  417620:	cmovge %eax,%edx
  417623:	mov    %dx,0x2(%r9)
  417628:	mov    %cx,(%r9)
  41762c:	repz retq 

000000000041762e <nextbit>:
  41762e:	mov    0x288(%rdi),%rcx
  417635:	cmpw   $0x0,0x2(%rcx)
  41763a:	jne    417673 <nextbit+0x45>
  41763c:	mov    0x2b0(%rdi),%rax
  417643:	test   %rax,%rax
  417646:	jle    41769b <nextbit+0x6d>
  417648:	sub    $0x1,%rax
  41764c:	mov    %rax,0x2b0(%rdi)
  417653:	mov    0x20(%rcx),%rdx
  417657:	mov    0x2a8(%rdi),%rax
  41765e:	lea    0x1(%rax),%rsi
  417662:	mov    %rsi,0x2a8(%rdi)
  417669:	movzbl (%rax),%eax
  41766c:	movzbl (%rdx,%rax,1),%eax
  417670:	mov    %ax,(%rcx)
  417673:	movzwl 0x2(%rcx),%edx
  417677:	movswl (%rcx),%eax
  41767a:	movswq %dx,%rsi
  41767e:	movzbl 0x41b510(%rsi),%esi
  417685:	and    %esi,%eax
  417687:	add    $0x1,%edx
  41768a:	cmp    $0x7,%dx
  41768e:	mov    $0x0,%esi
  417693:	cmovg  %esi,%edx
  417696:	mov    %dx,0x2(%rcx)
  41769a:	retq   
  41769b:	movzwl (%rcx),%eax
  41769e:	and    $0x80,%ax
  4176a2:	cwtl   
  4176a3:	movw   $0x1,0x2(%rcx)
  4176a9:	retq   

00000000004176aa <fillspan>:
  4176aa:	test   %edx,%edx
  4176ac:	jle    41770d <fillspan+0x63>
  4176ae:	mov    %esi,%eax
  4176b0:	sar    $0x3,%eax
  4176b3:	cltq   
  4176b5:	add    %rax,%rdi
  4176b8:	and    $0x7,%esi
  4176bb:	je     4176dc <fillspan+0x32>
  4176bd:	mov    $0x8,%eax
  4176c2:	sub    %esi,%eax
  4176c4:	cmp    %edx,%eax
  4176c6:	jg     41770f <fillspan+0x65>
  4176c8:	mov    $0xff,%r8d
  4176ce:	mov    %esi,%ecx
  4176d0:	sar    %cl,%r8d
  4176d3:	or     %r8b,(%rdi)
  4176d6:	sub    %eax,%edx
  4176d8:	lea    0x1(%rdi),%rdi
  4176dc:	cmp    $0x7,%edx
  4176df:	jle    417701 <fillspan+0x57>
  4176e1:	lea    -0x8(%rdx),%ecx
  4176e4:	shr    $0x3,%ecx
  4176e7:	mov    %ecx,%eax
  4176e9:	lea    0x1(%rdi,%rax,1),%rax
  4176ee:	add    $0x1,%rdi
  4176f2:	movb   $0xff,-0x1(%rdi)
  4176f6:	cmp    %rax,%rdi
  4176f9:	jne    4176ee <fillspan+0x44>
  4176fb:	neg    %ecx
  4176fd:	lea    -0x8(%rdx,%rcx,8),%edx
  417701:	movslq %edx,%rdx
  417704:	movzbl 0x41b4c0(%rdx),%eax
  41770b:	or     %al,(%rdi)
  41770d:	repz retq 
  41770f:	movslq %edx,%rdx
  417712:	movzbl 0x41b4c0(%rdx),%eax
  417719:	mov    %esi,%ecx
  41771b:	sar    %cl,%eax
  41771d:	or     %al,(%rdi)
  41771f:	retq   

0000000000417720 <decode_white_run>:
  417720:	mov    0x288(%rdi),%rsi
  417727:	movzwl 0x2(%rsi),%edx
  41772b:	mov    $0x0,%eax
  417730:	cmpw   $0x0,0x2(%rsi)
  417735:	jne    417773 <decode_white_run+0x53>
  417737:	mov    0x2b0(%rdi),%rcx
  41773e:	test   %rcx,%rcx
  417741:	jle    4177d6 <decode_white_run+0xb6>
  417747:	sub    $0x1,%rcx
  41774b:	mov    %rcx,0x2b0(%rdi)
  417752:	mov    0x20(%rsi),%r8
  417756:	mov    0x2a8(%rdi),%rcx
  41775d:	lea    0x1(%rcx),%r9
  417761:	mov    %r9,0x2a8(%rdi)
  417768:	movzbl (%rcx),%ecx
  41776b:	movzbl (%r8,%rcx,1),%ecx
  417770:	mov    %cx,(%rsi)
  417773:	movswq (%rsi),%r8
  417777:	movswq %dx,%rdx
  41777b:	shl    $0x8,%rdx
  41777f:	movzbl 0x62e640(%r8,%rdx,1),%ecx
  417788:	movzbl %cl,%r9d
  41778c:	movzbl 0x620040(%r8,%rdx,1),%edx
  417795:	test   %r9w,%r9w
  417799:	je     417737 <decode_white_run+0x17>
  41779b:	cmp    $0x1,%r9w
  4177a0:	je     4177dc <decode_white_run+0xbc>
  4177a2:	cmp    $0xd2,%r9w
  4177a8:	je     4177e2 <decode_white_run+0xc2>
  4177aa:	mov    %dx,0x2(%rsi)
  4177ae:	movzbl %cl,%ecx
  4177b1:	sub    $0x2,%ecx
  4177b4:	movslq %ecx,%rcx
  4177b7:	lea    (%rcx,%rcx,2),%rcx
  4177bb:	movzwl 0x641ee4(%rcx,%rcx,1),%ecx
  4177c3:	movswl %cx,%r8d
  4177c7:	add    %r8d,%eax
  4177ca:	cmp    $0x3f,%cx
  4177ce:	jg     417730 <decode_white_run+0x10>
  4177d4:	repz retq 
  4177d6:	mov    $0xfffffffc,%eax
  4177db:	retq   
  4177dc:	mov    $0xffffffff,%eax
  4177e1:	retq   
  4177e2:	mov    $0xfffffffd,%eax
  4177e7:	retq   

00000000004177e8 <decode_black_run>:
  4177e8:	mov    0x288(%rdi),%rsi
  4177ef:	movzwl 0x2(%rsi),%eax
  4177f3:	lea    0x8(%rax),%edx
  4177f6:	mov    $0x0,%eax
  4177fb:	cmpw   $0x0,0x2(%rsi)
  417800:	jne    41783e <decode_black_run+0x56>
  417802:	mov    0x2b0(%rdi),%rcx
  417809:	test   %rcx,%rcx
  41780c:	jle    4178a9 <decode_black_run+0xc1>
  417812:	sub    $0x1,%rcx
  417816:	mov    %rcx,0x2b0(%rdi)
  41781d:	mov    0x20(%rsi),%r8
  417821:	mov    0x2a8(%rdi),%rcx
  417828:	lea    0x1(%rcx),%r9
  41782c:	mov    %r9,0x2a8(%rdi)
  417833:	movzbl (%rcx),%ecx
  417836:	movzbl (%r8,%rcx,1),%ecx
  41783b:	mov    %cx,(%rsi)
  41783e:	movswq (%rsi),%r8
  417842:	movswq %dx,%rdx
  417846:	shl    $0x8,%rdx
  41784a:	movzbl 0x62e640(%r8,%rdx,1),%ecx
  417853:	movzbl %cl,%r9d
  417857:	movzbl 0x620040(%r8,%rdx,1),%r8d
  417860:	movzbl %r8b,%edx
  417864:	test   %r9w,%r9w
  417868:	je     417802 <decode_black_run+0x1a>
  41786a:	cmp    $0x1,%r9w
  41786f:	je     4178af <decode_black_run+0xc7>
  417871:	cmp    $0xd2,%r9w
  417877:	je     4178b5 <decode_black_run+0xcd>
  417879:	mov    %dx,0x2(%rsi)
  41787d:	movzbl %cl,%ecx
  417880:	sub    $0x6a,%ecx
  417883:	movslq %ecx,%rcx
  417886:	lea    (%rcx,%rcx,2),%rdx
  41788a:	movzwl 0x641ee4(%rdx,%rdx,1),%edx
  417892:	movswl %dx,%ecx
  417895:	add    %ecx,%eax
  417897:	cmp    $0x3f,%dx
  41789b:	jle    4178ba <decode_black_run+0xd2>
  41789d:	movzbl %r8b,%edx
  4178a1:	add    $0x8,%edx
  4178a4:	jmpq   4177fb <decode_black_run+0x13>
  4178a9:	mov    $0xfffffffc,%eax
  4178ae:	retq   
  4178af:	mov    $0xffffffff,%eax
  4178b4:	retq   
  4178b5:	mov    $0xfffffffd,%eax
  4178ba:	repz retq 

00000000004178bc <findspan>:
  4178bc:	mov    %rcx,%r9
  4178bf:	mov    (%rdi),%r8
  4178c2:	sub    %esi,%edx
  4178c4:	test   %edx,%edx
  4178c6:	jle    4178ff <findspan+0x43>
  4178c8:	and    $0x7,%esi
  4178cb:	je     417904 <findspan+0x48>
  4178cd:	movzbl (%r8),%eax
  4178d1:	mov    %esi,%ecx
  4178d3:	shl    %cl,%eax
  4178d5:	movzbl %al,%eax
  4178d8:	movzbl (%r9,%rax,1),%ecx
  4178dd:	mov    $0x8,%eax
  4178e2:	sub    %esi,%eax
  4178e4:	cmp    %edx,%eax
  4178e6:	cmovg  %edx,%eax
  4178e9:	cmp    %ecx,%eax
  4178eb:	cmovg  %ecx,%eax
  4178ee:	add    %eax,%esi
  4178f0:	cmp    $0x7,%esi
  4178f3:	jle    417937 <findspan+0x7b>
  4178f5:	sub    %eax,%edx
  4178f7:	add    $0x1,%r8
  4178fb:	mov    %eax,%esi
  4178fd:	jmp    417904 <findspan+0x48>
  4178ff:	mov    $0x0,%esi
  417904:	cmp    $0x7,%edx
  417907:	jle    41793b <findspan+0x7f>
  417909:	movzbl (%r8),%eax
  41790d:	movzbl (%r9,%rax,1),%ecx
  417912:	lea    (%rsi,%rcx,1),%eax
  417915:	sub    %ecx,%edx
  417917:	cmp    $0x7,%ecx
  41791a:	jle    417937 <findspan+0x7b>
  41791c:	add    $0x1,%r8
  417920:	cmp    $0x7,%edx
  417923:	jle    41793d <findspan+0x81>
  417925:	movzbl (%r8),%ecx
  417929:	movzbl (%r9,%rcx,1),%ecx
  41792e:	add    %ecx,%eax
  417930:	sub    %ecx,%edx
  417932:	cmp    $0x7,%ecx
  417935:	jg     41791c <findspan+0x60>
  417937:	mov    %r8,(%rdi)
  41793a:	retq   
  41793b:	mov    %esi,%eax
  41793d:	test   %edx,%edx
  41793f:	jle    417937 <findspan+0x7b>
  417941:	movzbl (%r8),%ecx
  417945:	movzbl (%r9,%rcx,1),%ecx
  41794a:	cmp    %edx,%ecx
  41794c:	cmovle %ecx,%edx
  41794f:	add    %edx,%eax
  417951:	jmp    417937 <findspan+0x7b>

0000000000417953 <finddiff>:
  417953:	push   %rbx
  417954:	sub    $0x8,%rsp
  417958:	mov    %rdi,(%rsp)
  41795c:	mov    %esi,%ebx
  41795e:	mov    %esi,%eax
  417960:	sar    $0x3,%eax
  417963:	cltq   
  417965:	add    %rax,(%rsp)
  417969:	test   %ecx,%ecx
  41796b:	mov    $0x61fe40,%ecx
  417970:	mov    $0x61ff40,%eax
  417975:	cmove  %rax,%rcx
  417979:	mov    %rsp,%rdi
  41797c:	callq  4178bc <findspan>
  417981:	add    %ebx,%eax
  417983:	add    $0x8,%rsp
  417987:	pop    %rbx
  417988:	retq   

0000000000417989 <Fax3Cleanup>:
  417989:	mov    0x288(%rdi),%rax
  417990:	test   %rax,%rax
  417993:	je     4179ae <Fax3Cleanup+0x25>
  417995:	push   %rbx
  417996:	mov    %rdi,%rbx
  417999:	mov    %rax,%rdi
  41799c:	callq  4010b0 <free@plt>
  4179a1:	movq   $0x0,0x288(%rbx)
  4179ac:	pop    %rbx
  4179ad:	retq   
  4179ae:	repz retq 

00000000004179b0 <putbits>:
  4179b0:	push   %r14
  4179b2:	push   %r13
  4179b4:	push   %r12
  4179b6:	push   %rbp
  4179b7:	push   %rbx
  4179b8:	mov    %rdi,%rbx
  4179bb:	mov    %esi,%r13d
  4179be:	mov    %edx,%r12d
  4179c1:	mov    0x288(%rdi),%rbp
  4179c8:	movzwl 0x2(%rbp),%eax
  4179cc:	movswl %ax,%ecx
  4179cf:	cmp    %ecx,%edx
  4179d1:	jbe    417a4c <putbits+0x9c>
  4179d3:	mov    $0x8,%r14d
  4179d9:	jmp    417a19 <putbits+0x69>
  4179db:	movswq 0x0(%rbp),%rax
  4179e0:	mov    0x20(%rbp),%rdx
  4179e4:	movzbl (%rdx,%rax,1),%edx
  4179e8:	mov    0x2a8(%rbx),%rax
  4179ef:	lea    0x1(%rax),%rcx
  4179f3:	mov    %rcx,0x2a8(%rbx)
  4179fa:	mov    %dl,(%rax)
  4179fc:	addq   $0x1,0x2b0(%rbx)
  417a04:	movw   $0x0,0x0(%rbp)
  417a0a:	movw   $0x8,0x2(%rbp)
  417a10:	mov    %r14d,%ecx
  417a13:	cmp    $0x8,%r12d
  417a17:	jbe    417a42 <putbits+0x92>
  417a19:	sub    %ecx,%r12d
  417a1c:	mov    %r13d,%eax
  417a1f:	mov    %r12d,%ecx
  417a22:	shr    %cl,%eax
  417a24:	or     %ax,0x0(%rbp)
  417a28:	mov    0x2a0(%rbx),%rax
  417a2f:	cmp    %rax,0x2b0(%rbx)
  417a36:	jl     4179db <putbits+0x2b>
  417a38:	mov    %rbx,%rdi
  417a3b:	callq  41425a <TIFFFlushData1>
  417a40:	jmp    4179db <putbits+0x2b>
  417a42:	mov    $0x8,%ecx
  417a47:	mov    $0x8,%eax
  417a4c:	mov    %r12d,%edx
  417a4f:	and    0x41b4e0(,%rdx,4),%r13d
  417a57:	sub    %r12d,%ecx
  417a5a:	shl    %cl,%r13d
  417a5d:	or     %r13w,0x0(%rbp)
  417a62:	sub    %r12d,%eax
  417a65:	mov    %ax,0x2(%rbp)
  417a69:	test   %ax,%ax
  417a6c:	jne    417ab3 <putbits+0x103>
  417a6e:	mov    0x2a0(%rbx),%rax
  417a75:	cmp    %rax,0x2b0(%rbx)
  417a7c:	jge    417abc <putbits+0x10c>
  417a7e:	movswq 0x0(%rbp),%rax
  417a83:	mov    0x20(%rbp),%rdx
  417a87:	movzbl (%rdx,%rax,1),%edx
  417a8b:	mov    0x2a8(%rbx),%rax
  417a92:	lea    0x1(%rax),%rcx
  417a96:	mov    %rcx,0x2a8(%rbx)
  417a9d:	mov    %dl,(%rax)
  417a9f:	addq   $0x1,0x2b0(%rbx)
  417aa7:	movw   $0x0,0x0(%rbp)
  417aad:	movw   $0x8,0x2(%rbp)
  417ab3:	pop    %rbx
  417ab4:	pop    %rbp
  417ab5:	pop    %r12
  417ab7:	pop    %r13
  417ab9:	pop    %r14
  417abb:	retq   
  417abc:	mov    %rbx,%rdi
  417abf:	callq  41425a <TIFFFlushData1>
  417ac4:	jmp    417a7e <putbits+0xce>

0000000000417ac6 <putcode>:
  417ac6:	sub    $0x8,%rsp
  417aca:	movzwl (%rsi),%edx
  417acd:	movzwl 0x2(%rsi),%esi
  417ad1:	callq  4179b0 <putbits>
  417ad6:	add    $0x8,%rsp
  417ada:	retq   

0000000000417adb <putspan>:
  417adb:	push   %r13
  417add:	push   %r12
  417adf:	push   %rbp
  417ae0:	push   %rbx
  417ae1:	sub    $0x8,%rsp
  417ae5:	mov    %rdi,%r12
  417ae8:	mov    %esi,%ebx
  417aea:	mov    %rdx,%rbp
  417aed:	cmp    $0xa3f,%esi
  417af3:	jle    417b18 <putspan+0x3d>
  417af5:	lea    0x26a(%rdx),%r13
  417afc:	mov    %r13,%rsi
  417aff:	mov    %r12,%rdi
  417b02:	callq  417ac6 <putcode>
  417b07:	movswl 0x26e(%rbp),%eax
  417b0e:	sub    %eax,%ebx
  417b10:	cmp    $0xa3f,%ebx
  417b16:	jg     417afc <putspan+0x21>
  417b18:	cmp    $0x3f,%ebx
  417b1b:	jle    417b4f <putspan+0x74>
  417b1d:	mov    %ebx,%eax
  417b1f:	sar    $0x6,%eax
  417b22:	lea    0x3f(%rax),%edx
  417b25:	movslq %edx,%rdx
  417b28:	lea    (%rdx,%rdx,2),%rdx
  417b2c:	lea    0x0(%rbp,%rdx,2),%r13
  417b31:	movswl 0x4(%r13),%edx
  417b36:	shl    $0x6,%eax
  417b39:	cmp    %eax,%edx
  417b3b:	jne    417b6e <putspan+0x93>
  417b3d:	mov    %r13,%rsi
  417b40:	mov    %r12,%rdi
  417b43:	callq  417ac6 <putcode>
  417b48:	movswl 0x4(%r13),%eax
  417b4d:	sub    %eax,%ebx
  417b4f:	movslq %ebx,%rbx
  417b52:	lea    (%rbx,%rbx,2),%rax
  417b56:	lea    0x0(%rbp,%rax,2),%rsi
  417b5b:	mov    %r12,%rdi
  417b5e:	callq  417ac6 <putcode>
  417b63:	add    $0x8,%rsp
  417b67:	pop    %rbx
  417b68:	pop    %rbp
  417b69:	pop    %r12
  417b6b:	pop    %r13
  417b6d:	retq   
  417b6e:	mov    $0x41b508,%ecx
  417b73:	mov    $0x315,%edx
  417b78:	mov    $0x41b518,%esi
  417b7d:	mov    $0x41b523,%edi
  417b82:	callq  4011b0 <__assert_fail@plt>

0000000000417b87 <Fax3Encode1DRow>:
  417b87:	push   %r14
  417b89:	push   %r13
  417b8b:	push   %r12
  417b8d:	push   %rbp
  417b8e:	push   %rbx
  417b8f:	sub    $0x10,%rsp
  417b93:	mov    %rdi,%r13
  417b96:	mov    %rsi,0x8(%rsp)
  417b9b:	mov    %edx,%ebp
  417b9d:	mov    0x288(%rdi),%r14
  417ba4:	mov    $0x0,%ebx
  417ba9:	mov    0x30(%r14),%rcx
  417bad:	mov    %ebp,%edx
  417baf:	mov    %ebx,%esi
  417bb1:	lea    0x8(%rsp),%rdi
  417bb6:	callq  4178bc <findspan>
  417bbb:	mov    %eax,%r12d
  417bbe:	mov    $0x641ee0,%edx
  417bc3:	mov    %eax,%esi
  417bc5:	mov    %r13,%rdi
  417bc8:	callq  417adb <putspan>
  417bcd:	add    %r12d,%ebx
  417bd0:	cmp    %ebx,%ebp
  417bd2:	jle    417bff <Fax3Encode1DRow+0x78>
  417bd4:	mov    0x38(%r14),%rcx
  417bd8:	mov    %ebp,%edx
  417bda:	mov    %ebx,%esi
  417bdc:	lea    0x8(%rsp),%rdi
  417be1:	callq  4178bc <findspan>
  417be6:	mov    %eax,%r12d
  417be9:	mov    $0x641c40,%edx
  417bee:	mov    %eax,%esi
  417bf0:	mov    %r13,%rdi
  417bf3:	callq  417adb <putspan>
  417bf8:	add    %r12d,%ebx
  417bfb:	cmp    %ebx,%ebp
  417bfd:	jg     417ba9 <Fax3Encode1DRow+0x22>
  417bff:	mov    $0x1,%eax
  417c04:	add    $0x10,%rsp
  417c08:	pop    %rbx
  417c09:	pop    %rbp
  417c0a:	pop    %r12
  417c0c:	pop    %r13
  417c0e:	pop    %r14
  417c10:	retq   

0000000000417c11 <Fax3PostEncode>:
  417c11:	push   %rbp
  417c12:	push   %rbx
  417c13:	sub    $0x8,%rsp
  417c17:	mov    0x288(%rdi),%rbp
  417c1e:	cmpw   $0x8,0x2(%rbp)
  417c23:	je     417c6d <Fax3PostEncode+0x5c>
  417c25:	mov    %rdi,%rbx
  417c28:	mov    0x2a0(%rdi),%rax
  417c2f:	cmp    %rax,0x2b0(%rdi)
  417c36:	jge    417c79 <Fax3PostEncode+0x68>
  417c38:	movswq 0x0(%rbp),%rax
  417c3d:	mov    0x20(%rbp),%rdx
  417c41:	movzbl (%rdx,%rax,1),%edx
  417c45:	mov    0x2a8(%rbx),%rax
  417c4c:	lea    0x1(%rax),%rcx
  417c50:	mov    %rcx,0x2a8(%rbx)
  417c57:	mov    %dl,(%rax)
  417c59:	addq   $0x1,0x2b0(%rbx)
  417c61:	movw   $0x0,0x0(%rbp)
  417c67:	movw   $0x8,0x2(%rbp)
  417c6d:	mov    $0x1,%eax
  417c72:	add    $0x8,%rsp
  417c76:	pop    %rbx
  417c77:	pop    %rbp
  417c78:	retq   
  417c79:	callq  41425a <TIFFFlushData1>
  417c7e:	jmp    417c38 <Fax3PostEncode+0x27>

0000000000417c80 <Fax3SetupState>:
  417c80:	push   %r13
  417c82:	push   %r12
  417c84:	push   %rbp
  417c85:	push   %rbx
  417c86:	sub    $0x8,%rsp
  417c8a:	mov    %rdi,%rbx
  417c8d:	cmpw   $0x1,0x62(%rdi)
  417c92:	jne    417d2a <Fax3SetupState+0xaa>
  417c98:	mov    %esi,%ebp
  417c9a:	testb  $0x80,0xe(%rdi)
  417c9e:	je     417d43 <Fax3SetupState+0xc3>
  417ca4:	callq  4133ab <TIFFTileRowSize>
  417ca9:	mov    %rax,%r12
  417cac:	mov    0x48(%rbx),%r13
  417cb0:	testb  $0x1,0xa8(%rbx)
  417cb7:	jne    417cc2 <Fax3SetupState+0x42>
  417cb9:	mov    %ebp,%edi
  417cbb:	cmpw   $0x4,0x66(%rbx)
  417cc0:	jne    417cc7 <Fax3SetupState+0x47>
  417cc2:	lea    0x1(%rbp,%r12,1),%edi
  417cc7:	mov    $0x0,%eax
  417ccc:	callq  401270 <malloc@plt>
  417cd1:	mov    %rax,0x288(%rbx)
  417cd8:	test   %rax,%rax
  417cdb:	je     417d54 <Fax3SetupState+0xd4>
  417cdd:	mov    %r12,0x8(%rax)
  417ce1:	mov    %r13,0x10(%rax)
  417ce5:	movsbl 0xc(%rbx),%ecx
  417ce9:	movzwl 0x6c(%rbx),%edx
  417ced:	cmp    %edx,%ecx
  417cef:	mov    $0x41a6c0,%edx
  417cf4:	mov    $0x41a5c0,%ecx
  417cf9:	cmove  %rcx,%rdx
  417cfd:	mov    %rdx,0x20(%rax)
  417d01:	cmpw   $0x1,0x68(%rbx)
  417d06:	sete   %dl
  417d09:	movzbl %dl,%ecx
  417d0c:	mov    %cx,0x4(%rax)
  417d10:	testb  $0x1,0xa8(%rbx)
  417d17:	jne    417d6d <Fax3SetupState+0xed>
  417d19:	cmpw   $0x4,0x66(%rbx)
  417d1e:	je     417d6d <Fax3SetupState+0xed>
  417d20:	movq   $0x0,0x28(%rax)
  417d28:	jmp    417d85 <Fax3SetupState+0x105>
  417d2a:	mov    $0x41b550,%esi
  417d2f:	mov    (%rdi),%rdi
  417d32:	mov    $0x0,%eax
  417d37:	callq  412a93 <TIFFError>
  417d3c:	mov    $0x0,%eax
  417d41:	jmp    417d85 <Fax3SetupState+0x105>
  417d43:	callq  412fcd <TIFFScanlineSize>
  417d48:	movslq %eax,%r12
  417d4b:	mov    0x30(%rbx),%r13
  417d4f:	jmpq   417cb0 <Fax3SetupState+0x30>
  417d54:	mov    (%rbx),%rdx
  417d57:	mov    $0x41b588,%esi
  417d5c:	mov    $0x41b53e,%edi
  417d61:	callq  412a93 <TIFFError>
  417d66:	mov    $0x0,%eax
  417d6b:	jmp    417d85 <Fax3SetupState+0x105>
  417d6d:	movslq %ebp,%rbp
  417d70:	mov    0x288(%rbx),%rcx
  417d77:	lea    0x1(%rcx,%rbp,1),%rcx
  417d7c:	mov    %rcx,0x28(%rax)
  417d80:	neg    %edx
  417d82:	mov    %dl,-0x1(%rcx)
  417d85:	add    $0x8,%rsp
  417d89:	pop    %rbx
  417d8a:	pop    %rbp
  417d8b:	pop    %r12
  417d8d:	pop    %r13
  417d8f:	retq   

0000000000417d90 <Fax3PreEncode>:
  417d90:	push   %rbx
  417d91:	mov    %rdi,%rbx
  417d94:	mov    0x288(%rdi),%rcx
  417d9b:	test   %rcx,%rcx
  417d9e:	je     417e29 <Fax3PreEncode+0x99>
  417da4:	movw   $0x8,0x2(%rcx)
  417daa:	movw   $0x0,(%rcx)
  417daf:	movl   $0x0,0x18(%rcx)
  417db6:	mov    0x28(%rcx),%rdx
  417dba:	test   %rdx,%rdx
  417dbd:	je     417de7 <Fax3PreEncode+0x57>
  417dbf:	cmpw   $0x1,0x4(%rcx)
  417dc4:	sbb    %eax,%eax
  417dc6:	not    %eax
  417dc8:	movzbl %al,%eax
  417dcb:	mov    0x8(%rcx),%rsi
  417dcf:	test   %esi,%esi
  417dd1:	jle    417de7 <Fax3PreEncode+0x57>
  417dd3:	lea    -0x1(%rsi),%esi
  417dd6:	lea    0x1(%rdx,%rsi,1),%rsi
  417ddb:	add    $0x1,%rdx
  417ddf:	mov    %al,-0x1(%rdx)
  417de2:	cmp    %rsi,%rdx
  417de5:	jne    417ddb <Fax3PreEncode+0x4b>
  417de7:	testb  $0x1,0xa8(%rbx)
  417dee:	je     417e8e <Fax3PreEncode+0xfe>
  417df4:	movss  0x94(%rbx),%xmm0
  417dfc:	cmpw   $0x3,0x98(%rbx)
  417e04:	je     417e71 <Fax3PreEncode+0xe1>
  417e06:	ucomiss 0x38db(%rip),%xmm0        # 41b6e8 <bitMask+0x1d8>
  417e0d:	seta   %al
  417e10:	movzbl %al,%eax
  417e13:	lea    0x2(%rax,%rax,1),%eax
  417e17:	mov    %ax,0x42(%rcx)
  417e1b:	sub    $0x1,%eax
  417e1e:	mov    %ax,0x40(%rcx)
  417e22:	mov    $0x1,%eax
  417e27:	pop    %rbx
  417e28:	retq   
  417e29:	mov    $0x48,%esi
  417e2e:	callq  417c80 <Fax3SetupState>
  417e33:	mov    %rax,%rcx
  417e36:	mov    $0x0,%eax
  417e3b:	test   %rcx,%rcx
  417e3e:	je     417e27 <Fax3PreEncode+0x97>
  417e40:	cmpw   $0x0,0x4(%rcx)
  417e45:	jne    417e5c <Fax3PreEncode+0xcc>
  417e47:	movq   $0x61ff40,0x30(%rcx)
  417e4f:	movq   $0x61fe40,0x38(%rcx)
  417e57:	jmpq   417da4 <Fax3PreEncode+0x14>
  417e5c:	movq   $0x61fe40,0x30(%rcx)
  417e64:	movq   $0x61ff40,0x38(%rcx)
  417e6c:	jmpq   417da4 <Fax3PreEncode+0x14>
  417e71:	cvtss2sd %xmm0,%xmm0
  417e75:	mulsd  0x385b(%rip),%xmm0        # 41b6d8 <bitMask+0x1c8>
  417e7d:	divsd  0x385b(%rip),%xmm0        # 41b6e0 <bitMask+0x1d0>
  417e85:	cvtsd2ss %xmm0,%xmm0
  417e89:	jmpq   417e06 <Fax3PreEncode+0x76>
  417e8e:	movw   $0x0,0x42(%rcx)
  417e94:	movw   $0x0,0x40(%rcx)
  417e9a:	mov    $0x1,%eax
  417e9f:	jmp    417e27 <Fax3PreEncode+0x97>

0000000000417ea1 <Fax3PreDecode>:
  417ea1:	push   %rbp
  417ea2:	push   %rbx
  417ea3:	sub    $0x8,%rsp
  417ea7:	mov    %rdi,%rbp
  417eaa:	mov    0x288(%rdi),%rbx
  417eb1:	test   %rbx,%rbx
  417eb4:	je     417f0b <Fax3PreDecode+0x6a>
  417eb6:	movw   $0x0,0x2(%rbx)
  417ebc:	movw   $0x0,(%rbx)
  417ec1:	movl   $0x0,0x18(%rbx)
  417ec8:	mov    0x28(%rbx),%rax
  417ecc:	test   %rax,%rax
  417ecf:	je     417ef9 <Fax3PreDecode+0x58>
  417ed1:	cmpw   $0x1,0x4(%rbx)
  417ed6:	sbb    %edx,%edx
  417ed8:	not    %edx
  417eda:	movzbl %dl,%edx
  417edd:	mov    0x8(%rbx),%rcx
  417ee1:	test   %ecx,%ecx
  417ee3:	jle    417ef9 <Fax3PreDecode+0x58>
  417ee5:	lea    -0x1(%rcx),%ecx
  417ee8:	lea    0x1(%rax,%rcx,1),%rcx
  417eed:	add    $0x1,%rax
  417ef1:	mov    %dl,-0x1(%rax)
  417ef4:	cmp    %rcx,%rax
  417ef7:	jne    417eed <Fax3PreDecode+0x4c>
  417ef9:	mov    $0x1,%eax
  417efe:	testb  $0x2,0xd(%rbp)
  417f02:	je     417f24 <Fax3PreDecode+0x83>
  417f04:	add    $0x8,%rsp
  417f08:	pop    %rbx
  417f09:	pop    %rbp
  417f0a:	retq   
  417f0b:	mov    $0x30,%esi
  417f10:	callq  417c80 <Fax3SetupState>
  417f15:	mov    %rax,%rbx
  417f18:	mov    $0x0,%eax
  417f1d:	test   %rbx,%rbx
  417f20:	jne    417eb6 <Fax3PreDecode+0x15>
  417f22:	jmp    417f04 <Fax3PreDecode+0x63>
  417f24:	mov    $0x0,%esi
  417f29:	mov    %rbp,%rdi
  417f2c:	callq  41744f <skiptoeol>
  417f31:	mov    $0x1,%eax
  417f36:	testb  $0x1,0xa8(%rbp)
  417f3d:	je     417f04 <Fax3PreDecode+0x63>
  417f3f:	mov    %rbp,%rdi
  417f42:	mov    $0x0,%eax
  417f47:	callq  41762e <nextbit>
  417f4c:	test   %eax,%eax
  417f4e:	sete   %al
  417f51:	movzbl %al,%eax
  417f54:	mov    %eax,0x18(%rbx)
  417f57:	mov    $0x1,%eax
  417f5c:	jmp    417f04 <Fax3PreDecode+0x63>

0000000000417f5e <TIFFInitCCITTFax3>:
  417f5e:	movq   $0x417ea1,0x228(%rdi)
  417f69:	movq   $0x418467,0x240(%rdi)
  417f74:	movq   $0x418467,0x250(%rdi)
  417f7f:	movq   $0x418467,0x260(%rdi)
  417f8a:	movq   $0x417d90,0x230(%rdi)
  417f95:	movq   $0x417c11,0x238(%rdi)
  417fa0:	movq   $0x4189c2,0x248(%rdi)
  417fab:	movq   $0x4189c2,0x258(%rdi)
  417fb6:	movq   $0x4189c2,0x268(%rdi)
  417fc1:	movq   $0x418741,0x270(%rdi)
  417fcc:	movq   $0x417989,0x280(%rdi)
  417fd7:	orb    $0x1,0xd(%rdi)
  417fdb:	orw    $0x20,0xe(%rdi)
  417fe0:	mov    $0x1,%eax
  417fe5:	retq   

0000000000417fe6 <TIFFModeCCITTFax3>:
  417fe6:	test   %esi,%esi
  417fe8:	jne    417ff0 <TIFFModeCCITTFax3+0xa>
  417fea:	andb   $0xfe,0xd(%rdi)
  417fee:	repz retq 
  417ff0:	orb    $0x1,0xd(%rdi)
  417ff4:	jmp    417fee <TIFFModeCCITTFax3+0x8>

0000000000417ff6 <Fax3Decode2DRow>:
  417ff6:	push   %r15
  417ff8:	push   %r14
  417ffa:	push   %r13
  417ffc:	push   %r12
  417ffe:	push   %rbp
  417fff:	push   %rbx
  418000:	sub    $0x18,%rsp
  418004:	mov    %rdi,%rbx
  418007:	mov    %rsi,(%rsp)
  41800b:	mov    %edx,%r13d
  41800e:	mov    0x288(%rdi),%rbp
  418015:	movzwl 0x4(%rbp),%r14d
  41801a:	mov    $0xffffffff,%r12d
  418020:	movzwl 0x2(%rbp),%eax
  418024:	test   %ax,%ax
  418027:	je     418067 <Fax3Decode2DRow+0x71>
  418029:	cmp    $0x7,%ax
  41802d:	jg     418067 <Fax3Decode2DRow+0x71>
  41802f:	movswq 0x0(%rbp),%rdx
  418034:	movswq 0x2(%rbp),%rax
  418039:	shl    $0x8,%rax
  41803d:	movzbl 0x640840(%rdx,%rax,1),%r15d
  418046:	movzbl 0x63f440(%rdx,%rax,1),%eax
  41804e:	mov    %ax,0x2(%rbp)
  418052:	cmp    $0xc,%r15b
  418056:	ja     418428 <Fax3Decode2DRow+0x432>
  41805c:	movzbl %r15b,%eax
  418060:	jmpq   *0x41b3e0(,%rax,8)
  418067:	mov    0x2b0(%rbx),%rax
  41806e:	test   %rax,%rax
  418071:	jle    4180a1 <Fax3Decode2DRow+0xab>
  418073:	sub    $0x1,%rax
  418077:	mov    %rax,0x2b0(%rbx)
  41807e:	mov    0x20(%rbp),%rdx
  418082:	mov    0x2a8(%rbx),%rax
  418089:	lea    0x1(%rax),%rcx
  41808d:	mov    %rcx,0x2a8(%rbx)
  418094:	movzbl (%rax),%eax
  418097:	movzbl (%rdx,%rax,1),%eax
  41809b:	mov    %ax,0x0(%rbp)
  41809f:	jmp    41802f <Fax3Decode2DRow+0x39>
  4180a1:	mov    0x1f8(%rbx),%rcx
  4180a8:	mov    (%rbx),%rdx
  4180ab:	mov    $0x41b5b0,%esi
  4180b0:	mov    $0x61fde0,%edi
  4180b5:	mov    $0x0,%eax
  4180ba:	callq  412a93 <TIFFError>
  4180bf:	mov    $0x0,%eax
  4180c4:	jmpq   4183e4 <Fax3Decode2DRow+0x3ee>
  4180c9:	test   %r14w,%r14w
  4180cd:	sete   %r15b
  4180d1:	movzbl %r15b,%r15d
  4180d5:	mov    0x28(%rbp),%rdi
  4180d9:	mov    %r15d,%ecx
  4180dc:	mov    %r13d,%edx
  4180df:	mov    %r12d,%esi
  4180e2:	callq  417953 <finddiff>
  4180e7:	movswl %r14w,%ecx
  4180eb:	mov    0x28(%rbp),%rdi
  4180ef:	mov    %r13d,%edx
  4180f2:	mov    %eax,%esi
  4180f4:	callq  417953 <finddiff>
  4180f9:	mov    0x28(%rbp),%rdi
  4180fd:	mov    %r15d,%ecx
  418100:	mov    %r13d,%edx
  418103:	mov    %eax,%esi
  418105:	callq  417953 <finddiff>
  41810a:	mov    %eax,%r15d
  41810d:	test   %r14w,%r14w
  418111:	je     41844d <Fax3Decode2DRow+0x457>
  418117:	test   %r12d,%r12d
  41811a:	mov    $0x0,%esi
  41811f:	cmovns %r12d,%esi
  418123:	mov    %eax,%edx
  418125:	sub    %esi,%edx
  418127:	mov    (%rsp),%rdi
  41812b:	callq  4176aa <fillspan>
  418130:	mov    %r15d,%r12d
  418133:	jmp    4181b3 <Fax3Decode2DRow+0x1bd>
  418135:	cmp    %r14w,0x4(%rbp)
  41813a:	je     4181c1 <Fax3Decode2DRow+0x1cb>
  418140:	mov    %rbx,%rdi
  418143:	mov    $0x0,%eax
  418148:	callq  4177e8 <decode_black_run>
  41814d:	mov    %eax,0xc(%rsp)
  418151:	mov    %rbx,%rdi
  418154:	mov    $0x0,%eax
  418159:	callq  417720 <decode_white_run>
  41815e:	mov    %eax,%r15d
  418161:	test   %r12d,%r12d
  418164:	mov    $0x0,%eax
  418169:	cmovs  %eax,%r12d
  41816d:	mov    0xc(%rsp),%edi
  418171:	lea    (%rdi,%r12,1),%edx
  418175:	mov    %r13d,%eax
  418178:	sub    %r12d,%eax
  41817b:	cmp    %r13d,%edx
  41817e:	cmovle %edi,%eax
  418181:	mov    %eax,0xc(%rsp)
  418185:	test   %r14w,%r14w
  418189:	jne    4181e7 <Fax3Decode2DRow+0x1f1>
  41818b:	add    0xc(%rsp),%r12d
  418190:	lea    (%r15,%r12,1),%edx
  418194:	mov    %r13d,%eax
  418197:	sub    %r12d,%eax
  41819a:	cmp    %edx,%r13d
  41819d:	cmovl  %eax,%r15d
  4181a1:	mov    %r15d,%edx
  4181a4:	mov    %r12d,%esi
  4181a7:	mov    (%rsp),%rdi
  4181ab:	callq  4176aa <fillspan>
  4181b0:	add    %r15d,%r12d
  4181b3:	cmp    %r13d,%r12d
  4181b6:	jl     418020 <Fax3Decode2DRow+0x2a>
  4181bc:	jmpq   4183d5 <Fax3Decode2DRow+0x3df>
  4181c1:	mov    %rbx,%rdi
  4181c4:	mov    $0x0,%eax
  4181c9:	callq  417720 <decode_white_run>
  4181ce:	mov    %eax,0xc(%rsp)
  4181d2:	mov    %rbx,%rdi
  4181d5:	mov    $0x0,%eax
  4181da:	callq  4177e8 <decode_black_run>
  4181df:	mov    %eax,%r15d
  4181e2:	jmpq   418161 <Fax3Decode2DRow+0x16b>
  4181e7:	mov    %eax,%edx
  4181e9:	mov    %r12d,%esi
  4181ec:	mov    (%rsp),%rdi
  4181f0:	callq  4176aa <fillspan>
  4181f5:	add    0xc(%rsp),%r12d
  4181fa:	lea    (%r12,%r15,1),%edx
  4181fe:	mov    %r13d,%eax
  418201:	sub    %r12d,%eax
  418204:	cmp    %edx,%r13d
  418207:	cmovl  %eax,%r15d
  41820b:	jmp    4181b0 <Fax3Decode2DRow+0x1ba>
  41820d:	test   %r14w,%r14w
  418211:	sete   0xc(%rsp)
  418216:	movzbl 0xc(%rsp),%eax
  41821b:	movzbl %al,%ecx
  41821e:	mov    0x28(%rbp),%rdi
  418222:	mov    %r13d,%edx
  418225:	mov    %r12d,%esi
  418228:	callq  417953 <finddiff>
  41822d:	movswl %r14w,%ecx
  418231:	mov    0x28(%rbp),%rdi
  418235:	mov    %r13d,%edx
  418238:	mov    %eax,%esi
  41823a:	callq  417953 <finddiff>
  41823f:	movzbl %r15b,%r15d
  418243:	lea    -0x6(%rax,%r15,1),%r15d
  418248:	test   %r14w,%r14w
  41824c:	je     418268 <Fax3Decode2DRow+0x272>
  41824e:	test   %r12d,%r12d
  418251:	mov    $0x0,%esi
  418256:	cmovns %r12d,%esi
  41825a:	mov    %r15d,%edx
  41825d:	sub    %esi,%edx
  41825f:	mov    (%rsp),%rdi
  418263:	callq  4176aa <fillspan>
  418268:	movzbl 0xc(%rsp),%r14d
  41826e:	mov    %r15d,%r12d
  418271:	jmpq   4181b3 <Fax3Decode2DRow+0x1bd>
  418276:	test   %r12d,%r12d
  418279:	mov    $0x0,%eax
  41827e:	cmovs  %eax,%r12d
  418282:	jmpq   418331 <Fax3Decode2DRow+0x33b>
  418287:	mov    0x2b0(%rbx),%rdx
  41828e:	test   %rdx,%rdx
  418291:	jle    41838c <Fax3Decode2DRow+0x396>
  418297:	sub    $0x1,%rdx
  41829b:	mov    %rdx,0x2b0(%rbx)
  4182a2:	mov    0x20(%rax),%rcx
  4182a6:	mov    0x2a8(%rbx),%rdx
  4182ad:	lea    0x1(%rdx),%rsi
  4182b1:	mov    %rsi,0x2a8(%rbx)
  4182b8:	movzbl (%rdx),%edx
  4182bb:	movzbl (%rcx,%rdx,1),%edx
  4182bf:	mov    %dx,(%rax)
  4182c2:	movswq (%rax),%rcx
  4182c6:	movswq 0x2(%rax),%rdx
  4182cb:	shl    $0x8,%rdx
  4182cf:	movzbl 0x63e040(%rcx,%rdx,1),%r15d
  4182d8:	movzbl 0x63cc40(%rcx,%rdx,1),%edx
  4182e0:	mov    %dx,0x2(%rax)
  4182e4:	test   %r15b,%r15b
  4182e7:	jne    4182fa <Fax3Decode2DRow+0x304>
  4182e9:	movzwl 0x2(%rax),%edx
  4182ed:	test   %dx,%dx
  4182f0:	je     418287 <Fax3Decode2DRow+0x291>
  4182f2:	cmp    $0x7,%dx
  4182f6:	jle    4182c2 <Fax3Decode2DRow+0x2cc>
  4182f8:	jmp    418287 <Fax3Decode2DRow+0x291>
  4182fa:	movzbl %r15b,%edx
  4182fe:	cmp    $0xe,%r15b
  418302:	ja     418327 <Fax3Decode2DRow+0x331>
  418304:	movzbl %r15b,%eax
  418308:	jmpq   *0x41b448(,%rax,8)
  41830f:	lea    -0x1(%rdx,%r12,1),%r12d
  418314:	lea    -0x1(%r12),%esi
  418319:	mov    $0x1,%edx
  41831e:	mov    (%rsp),%rdi
  418322:	callq  4176aa <fillspan>
  418327:	cmp    $0x7,%r15b
  41832b:	ja     4181b3 <Fax3Decode2DRow+0x1bd>
  418331:	mov    0x288(%rbx),%rax
  418338:	jmp    4182e9 <Fax3Decode2DRow+0x2f3>
  41833a:	add    $0x5,%r12d
  41833e:	jmp    418331 <Fax3Decode2DRow+0x33b>
  418340:	lea    -0x8(%rdx,%r12,1),%r12d
  418345:	mov    %rbx,%rdi
  418348:	mov    $0x0,%eax
  41834d:	callq  41762e <nextbit>
  418352:	test   %eax,%eax
  418354:	je     418365 <Fax3Decode2DRow+0x36f>
  418356:	cmpw   $0x0,0x4(%rbp)
  41835b:	sete   %r14b
  41835f:	movzbl %r14b,%r14d
  418363:	jmp    418327 <Fax3Decode2DRow+0x331>
  418365:	movzwl 0x4(%rbp),%r14d
  41836a:	jmp    418327 <Fax3Decode2DRow+0x331>
  41836c:	mov    0x1f8(%rbx),%rcx
  418373:	mov    (%rbx),%rdx
  418376:	mov    $0x41b5d8,%esi
  41837b:	mov    $0x61fde0,%edi
  418380:	mov    $0x0,%eax
  418385:	callq  412a93 <TIFFError>
  41838a:	jmp    4183d5 <Fax3Decode2DRow+0x3df>
  41838c:	mov    0x1f8(%rbx),%rcx
  418393:	mov    (%rbx),%rdx
  418396:	mov    $0x41b5b0,%esi
  41839b:	mov    $0x61fde0,%edi
  4183a0:	mov    $0x0,%eax
  4183a5:	callq  412a93 <TIFFError>
  4183aa:	mov    $0x0,%eax
  4183af:	jmp    4183e4 <Fax3Decode2DRow+0x3ee>
  4183b1:	testb  $0x2,0xd(%rbx)
  4183b5:	je     4183f3 <Fax3Decode2DRow+0x3fd>
  4183b7:	mov    0x1f8(%rbx),%rcx
  4183be:	mov    (%rbx),%rdx
  4183c1:	mov    $0x41b630,%esi
  4183c6:	mov    $0x61fde0,%edi
  4183cb:	mov    $0x0,%eax
  4183d0:	callq  412a93 <TIFFError>
  4183d5:	testb  $0x2,0xd(%rbx)
  4183d9:	je     418455 <Fax3Decode2DRow+0x45f>
  4183db:	cmp    %r13d,%r12d
  4183de:	setge  %al
  4183e1:	movzbl %al,%eax
  4183e4:	add    $0x18,%rsp
  4183e8:	pop    %rbx
  4183e9:	pop    %rbp
  4183ea:	pop    %r12
  4183ec:	pop    %r13
  4183ee:	pop    %r14
  4183f0:	pop    %r15
  4183f2:	retq   
  4183f3:	mov    0x1f8(%rbx),%rcx
  4183fa:	mov    %r12d,%r8d
  4183fd:	mov    (%rbx),%rdx
  418400:	mov    $0x41b608,%esi
  418405:	mov    $0x61fde0,%edi
  41840a:	mov    $0x0,%eax
  41840f:	callq  413526 <TIFFWarning>
  418414:	mov    $0x7,%esi
  418419:	mov    %rbx,%rdi
  41841c:	callq  41744f <skiptoeol>
  418421:	mov    $0x1,%eax
  418426:	jmp    4183e4 <Fax3Decode2DRow+0x3ee>
  418428:	mov    0x1f8(%rbx),%rcx
  41842f:	mov    (%rbx),%rdx
  418432:	mov    $0x41b658,%esi
  418437:	mov    $0x61fde0,%edi
  41843c:	mov    $0x0,%eax
  418441:	callq  412a93 <TIFFError>
  418446:	mov    $0x0,%eax
  41844b:	jmp    4183e4 <Fax3Decode2DRow+0x3ee>
  41844d:	mov    %eax,%r12d
  418450:	jmpq   4181b3 <Fax3Decode2DRow+0x1bd>
  418455:	mov    $0x0,%esi
  41845a:	mov    %rbx,%rdi
  41845d:	callq  41744f <skiptoeol>
  418462:	jmpq   4183db <Fax3Decode2DRow+0x3e5>

0000000000418467 <Fax3Decode>:
  418467:	push   %r15
  418469:	push   %r14
  41846b:	push   %r13
  41846d:	push   %r12
  41846f:	push   %rbp
  418470:	push   %rbx
  418471:	sub    $0x28,%rsp
  418475:	mov    %rdi,%rbx
  418478:	mov    %rsi,%r13
  41847b:	mov    %edx,%r15d
  41847e:	mov    %edx,0xc(%rsp)
  418482:	mov    0x288(%rdi),%rbp
  418489:	mov    %edx,%esi
  41848b:	mov    %r13,%rdi
  41848e:	mov    $0x0,%eax
  418493:	callq  4012f0 <bzero@plt>
  418498:	test   %r15d,%r15d
  41849b:	jg     4185e4 <Fax3Decode+0x17d>
  4184a1:	mov    $0x1,%eax
  4184a6:	jmp    4184e5 <Fax3Decode+0x7e>
  4184a8:	mov    %rbx,%rdi
  4184ab:	mov    $0x0,%eax
  4184b0:	callq  417720 <decode_white_run>
  4184b5:	mov    %eax,%r12d
  4184b8:	jmpq   418626 <Fax3Decode+0x1bf>
  4184bd:	mov    0x1f8(%rbx),%rcx
  4184c4:	mov    0x10(%rsp),%r8d
  4184c9:	mov    (%rbx),%rdx
  4184cc:	mov    $0x41b688,%esi
  4184d1:	mov    $0x61fdf0,%edi
  4184d6:	mov    $0x0,%eax
  4184db:	callq  412a93 <TIFFError>
  4184e0:	mov    $0x0,%eax
  4184e5:	add    $0x28,%rsp
  4184e9:	pop    %rbx
  4184ea:	pop    %rbp
  4184eb:	pop    %r12
  4184ed:	pop    %r13
  4184ef:	pop    %r14
  4184f1:	pop    %r15
  4184f3:	retq   
  4184f4:	mov    0x1f8(%rbx),%rcx
  4184fb:	mov    0x10(%rsp),%r8d
  418500:	mov    (%rbx),%rdx
  418503:	mov    $0x41b6b0,%esi
  418508:	mov    $0x61fdf0,%edi
  41850d:	mov    $0x0,%eax
  418512:	callq  412a93 <TIFFError>
  418517:	testb  $0x2,0xd(%rbx)
  41851b:	je     418596 <Fax3Decode+0x12f>
  41851d:	testb  $0x4,0xd(%rbx)
  418521:	je     41852a <Fax3Decode+0xc3>
  418523:	movw   $0x0,0x2(%r15)
  41852a:	testb  $0x8,0xd(%rbx)
  41852e:	je     41854e <Fax3Decode+0xe7>
  418530:	mov    0x2a8(%rbx),%rax
  418537:	test   $0x1,%al
  418539:	je     41854e <Fax3Decode+0xe7>
  41853b:	subq   $0x1,0x2b0(%rbx)
  418543:	add    $0x1,%rax
  418547:	mov    %rax,0x2a8(%rbx)
  41854e:	mov    0x10(%rsp),%eax
  418552:	cmp    %eax,0x18(%rsp)
  418556:	je     4185be <Fax3Decode+0x157>
  418558:	mov    $0x0,%eax
  41855d:	jmp    4184e5 <Fax3Decode+0x7e>
  41855f:	mov    0x1f8(%rbx),%rcx
  418566:	mov    0x10(%rsp),%r8d
  41856b:	mov    (%rbx),%rdx
  41856e:	mov    $0x41b608,%esi
  418573:	mov    $0x61fdf0,%edi
  418578:	mov    $0x0,%eax
  41857d:	callq  413526 <TIFFWarning>
  418582:	jmp    4185be <Fax3Decode+0x157>
  418584:	mov    %r12d,%edx
  418587:	mov    %edi,%esi
  418589:	mov    %r13,%rdi
  41858c:	callq  4176aa <fillspan>
  418591:	jmpq   418669 <Fax3Decode+0x202>
  418596:	mov    $0x0,%esi
  41859b:	mov    %rbx,%rdi
  41859e:	callq  41744f <skiptoeol>
  4185a3:	jmpq   41851d <Fax3Decode+0xb6>
  4185a8:	mov    0x10(%rbp),%edx
  4185ab:	mov    %r13,%rsi
  4185ae:	mov    %rbx,%rdi
  4185b1:	callq  417ff6 <Fax3Decode2DRow>
  4185b6:	test   %eax,%eax
  4185b8:	je     4184e5 <Fax3Decode+0x7e>
  4185be:	testb  $0x1,0xa8(%rbx)
  4185c5:	jne    41868a <Fax3Decode+0x223>
  4185cb:	mov    0x8(%rbp),%rax
  4185cf:	add    %rax,%r13
  4185d2:	mov    0xc(%rsp),%esi
  4185d6:	sub    %eax,%esi
  4185d8:	mov    %esi,0xc(%rsp)
  4185dc:	test   %esi,%esi
  4185de:	jle    4186bd <Fax3Decode+0x256>
  4185e4:	cmpl   $0x0,0x18(%rbp)
  4185e8:	jne    4185a8 <Fax3Decode+0x141>
  4185ea:	mov    0x10(%rbp),%rax
  4185ee:	mov    %rax,0x18(%rsp)
  4185f3:	mov    %eax,0x14(%rsp)
  4185f7:	mov    0x288(%rbx),%r15
  4185fe:	movzwl 0x4(%r15),%r14d
  418603:	movl   $0x0,0x10(%rsp)
  41860b:	cmp    %r14w,0x4(%r15)
  418610:	je     4184a8 <Fax3Decode+0x41>
  418616:	mov    %rbx,%rdi
  418619:	mov    $0x0,%eax
  41861e:	callq  4177e8 <decode_black_run>
  418623:	mov    %eax,%r12d
  418626:	cmp    $0xfffffffd,%r12d
  41862a:	je     41855f <Fax3Decode+0xf8>
  418630:	cmp    $0xffffffff,%r12d
  418634:	je     4184f4 <Fax3Decode+0x8d>
  41863a:	cmp    $0xfffffffc,%r12d
  41863e:	je     4184bd <Fax3Decode+0x56>
  418644:	mov    0x10(%rsp),%edi
  418648:	lea    (%r12,%rdi,1),%edx
  41864c:	mov    0x14(%rsp),%ecx
  418650:	mov    %ecx,%eax
  418652:	sub    %edi,%eax
  418654:	cmp    %edx,%ecx
  418656:	cmovl  %eax,%r12d
  41865a:	test   %r12d,%r12d
  41865d:	jle    41867c <Fax3Decode+0x215>
  41865f:	test   %r14w,%r14w
  418663:	jne    418584 <Fax3Decode+0x11d>
  418669:	add    %r12d,0x10(%rsp)
  41866e:	mov    0x10(%rsp),%eax
  418672:	cmp    %eax,0x14(%rsp)
  418676:	jle    418517 <Fax3Decode+0xb0>
  41867c:	test   %r14w,%r14w
  418680:	sete   %r14b
  418684:	movzbl %r14b,%r14d
  418688:	jmp    41860b <Fax3Decode+0x1a4>
  41868a:	mov    %rbx,%rdi
  41868d:	mov    $0x0,%eax
  418692:	callq  41762e <nextbit>
  418697:	test   %eax,%eax
  418699:	sete   %dl
  41869c:	movzbl %dl,%edx
  41869f:	mov    %edx,0x18(%rbp)
  4186a2:	jne    4185cb <Fax3Decode+0x164>
  4186a8:	mov    0x8(%rbp),%rdx
  4186ac:	mov    0x28(%rbp),%rsi
  4186b0:	mov    %r13,%rdi
  4186b3:	callq  4012d0 <bcopy@plt>
  4186b8:	jmpq   4185cb <Fax3Decode+0x164>
  4186bd:	mov    $0x1,%eax
  4186c2:	jmpq   4184e5 <Fax3Decode+0x7e>

00000000004186c7 <Fax3PutEOL>:
  4186c7:	push   %rbp
  4186c8:	push   %rbx
  4186c9:	sub    $0x8,%rsp
  4186cd:	mov    %rdi,%rbx
  4186d0:	mov    0x288(%rdi),%rbp
  4186d7:	testb  $0x4,0xa8(%rdi)
  4186de:	je     418704 <Fax3PutEOL+0x3d>
  4186e0:	movzwl 0x2(%rbp),%ecx
  4186e4:	cmp    $0x4,%cx
  4186e8:	je     418704 <Fax3PutEOL+0x3d>
  4186ea:	movswl %cx,%eax
  4186ed:	lea    0x4(%rax),%edx
  4186f0:	sub    $0x4,%eax
  4186f3:	cmp    $0x3,%cx
  4186f7:	cmovg  %eax,%edx
  4186fa:	mov    $0x0,%esi
  4186ff:	callq  4179b0 <putbits>
  418704:	mov    $0xc,%edx
  418709:	mov    $0x1,%esi
  41870e:	mov    %rbx,%rdi
  418711:	callq  4179b0 <putbits>
  418716:	testb  $0x1,0xa8(%rbx)
  41871d:	jne    418726 <Fax3PutEOL+0x5f>
  41871f:	add    $0x8,%rsp
  418723:	pop    %rbx
  418724:	pop    %rbp
  418725:	retq   
  418726:	cmpl   $0x0,0x18(%rbp)
  41872a:	sete   %sil
  41872e:	movzbl %sil,%esi
  418732:	mov    $0x1,%edx
  418737:	mov    %rbx,%rdi
  41873a:	callq  4179b0 <putbits>
  41873f:	jmp    41871f <Fax3PutEOL+0x58>

0000000000418741 <Fax3Close>:
  418741:	testb  $0x1,0xd(%rdi)
  418745:	jne    418771 <Fax3Close+0x30>
  418747:	push   %rbp
  418748:	push   %rbx
  418749:	sub    $0x8,%rsp
  41874d:	mov    %rdi,%rbp
  418750:	mov    $0x6,%ebx
  418755:	mov    %rbp,%rdi
  418758:	callq  4186c7 <Fax3PutEOL>
  41875d:	sub    $0x1,%ebx
  418760:	jne    418755 <Fax3Close+0x14>
  418762:	mov    %rbp,%rdi
  418765:	callq  417c11 <Fax3PostEncode>
  41876a:	add    $0x8,%rsp
  41876e:	pop    %rbx
  41876f:	pop    %rbp
  418770:	retq   
  418771:	repz retq 

0000000000418773 <Fax3Encode2DRow>:
  418773:	push   %r15
  418775:	push   %r14
  418777:	push   %r13
  418779:	push   %r12
  41877b:	push   %rbp
  41877c:	push   %rbx
  41877d:	sub    $0x18,%rsp
  418781:	mov    %rdi,(%rsp)
  418785:	mov    %rsi,%r15
  418788:	mov    %rdx,%r14
  41878b:	mov    %ecx,%r12d
  41878e:	mov    0x288(%rdi),%rax
  418795:	movswl 0x4(%rax),%edi
  418799:	mov    %edi,0xc(%rsp)
  41879d:	movzbl (%rsi),%eax
  4187a0:	shr    $0x7,%al
  4187a3:	movzbl %al,%eax
  4187a6:	mov    $0x0,%r13d
  4187ac:	cmp    %edi,%eax
  4187ae:	je     4187cf <Fax3Encode2DRow+0x5c>
  4187b0:	movzbl (%r14),%eax
  4187b4:	shr    $0x7,%al
  4187b7:	movzbl %al,%eax
  4187ba:	mov    $0x0,%ebx
  4187bf:	cmp    %eax,0xc(%rsp)
  4187c3:	je     4187e6 <Fax3Encode2DRow+0x73>
  4187c5:	mov    $0x0,%ebp
  4187ca:	jmpq   4188c2 <Fax3Encode2DRow+0x14f>
  4187cf:	mov    %edi,%ecx
  4187d1:	mov    %r12d,%edx
  4187d4:	mov    $0x0,%esi
  4187d9:	mov    %r15,%rdi
  4187dc:	callq  417953 <finddiff>
  4187e1:	mov    %eax,%r13d
  4187e4:	jmp    4187b0 <Fax3Encode2DRow+0x3d>
  4187e6:	mov    0xc(%rsp),%ecx
  4187ea:	mov    %r12d,%edx
  4187ed:	mov    $0x0,%esi
  4187f2:	mov    %r14,%rdi
  4187f5:	callq  417953 <finddiff>
  4187fa:	mov    %eax,%ebx
  4187fc:	jmp    4187c5 <Fax3Encode2DRow+0x52>
  4187fe:	mov    %r13d,%esi
  418801:	sub    %ebp,%esi
  418803:	mov    $0x641c40,%edx
  418808:	mov    (%rsp),%rbp
  41880c:	mov    %rbp,%rdi
  41880f:	callq  417adb <putspan>
  418814:	mov    %ebx,%esi
  418816:	sub    %r13d,%esi
  418819:	mov    $0x641ee0,%edx
  41881e:	mov    %rbp,%rdi
  418821:	callq  417adb <putspan>
  418826:	mov    %ebx,%ebp
  418828:	jmp    418848 <Fax3Encode2DRow+0xd5>
  41882a:	add    $0x3,%ebx
  41882d:	movslq %ebx,%rbx
  418830:	lea    (%rbx,%rbx,2),%rax
  418834:	lea    0x61fe00(%rax,%rax,1),%rsi
  41883c:	mov    (%rsp),%rdi
  418840:	callq  417ac6 <putcode>
  418845:	mov    %r13d,%ebp
  418848:	cmp    %r12d,%ebp
  41884b:	jge    4189ae <Fax3Encode2DRow+0x23b>
  418851:	mov    %ebp,%ebx
  418853:	sar    $0x3,%ebx
  418856:	movslq %ebx,%rbx
  418859:	add    %r15,%rbx
  41885c:	mov    %ebp,%eax
  41885e:	not    %eax
  418860:	and    $0x7,%eax
  418863:	mov    %eax,%edi
  418865:	movzbl (%rbx),%eax
  418868:	mov    %edi,0x8(%rsp)
  41886c:	mov    %edi,%ecx
  41886e:	sar    %cl,%eax
  418870:	mov    %eax,%ecx
  418872:	and    $0x1,%ecx
  418875:	mov    %r12d,%edx
  418878:	mov    %ebp,%esi
  41887a:	mov    %r15,%rdi
  41887d:	callq  417953 <finddiff>
  418882:	mov    %eax,%r13d
  418885:	movzbl (%rbx),%eax
  418888:	movzbl 0x8(%rsp),%ecx
  41888d:	sar    %cl,%eax
  41888f:	test   $0x1,%al
  418891:	sete   %cl
  418894:	movzbl %cl,%ecx
  418897:	mov    %r12d,%edx
  41889a:	mov    %ebp,%esi
  41889c:	mov    %r14,%rdi
  41889f:	callq  417953 <finddiff>
  4188a4:	movzbl (%rbx),%edx
  4188a7:	movzbl 0x8(%rsp),%ecx
  4188ac:	sar    %cl,%edx
  4188ae:	mov    %edx,%ecx
  4188b0:	and    $0x1,%ecx
  4188b3:	mov    %r12d,%edx
  4188b6:	mov    %eax,%esi
  4188b8:	mov    %r14,%rdi
  4188bb:	callq  417953 <finddiff>
  4188c0:	mov    %eax,%ebx
  4188c2:	mov    %ebx,%eax
  4188c4:	sar    $0x3,%eax
  4188c7:	cltq   
  4188c9:	movzbl (%r14,%rax,1),%eax
  4188ce:	mov    %ebx,%ecx
  4188d0:	not    %ecx
  4188d2:	and    $0x7,%ecx
  4188d5:	sar    %cl,%eax
  4188d7:	mov    %eax,%ecx
  4188d9:	and    $0x1,%ecx
  4188dc:	mov    %r12d,%edx
  4188df:	mov    %ebx,%esi
  4188e1:	mov    %r14,%rdi
  4188e4:	callq  417953 <finddiff>
  4188e9:	mov    %eax,0x8(%rsp)
  4188ed:	cmp    %eax,%r13d
  4188f0:	jg     418997 <Fax3Encode2DRow+0x224>
  4188f6:	sub    %r13d,%ebx
  4188f9:	lea    0x3(%rbx),%eax
  4188fc:	cmp    $0x6,%eax
  4188ff:	jbe    41882a <Fax3Encode2DRow+0xb7>
  418905:	mov    %r13d,%eax
  418908:	sar    $0x3,%eax
  41890b:	cltq   
  41890d:	movzbl (%r15,%rax,1),%eax
  418912:	mov    %r13d,%ecx
  418915:	not    %ecx
  418917:	and    $0x7,%ecx
  41891a:	sar    %cl,%eax
  41891c:	mov    %eax,%ecx
  41891e:	and    $0x1,%ecx
  418921:	mov    %r12d,%edx
  418924:	mov    %r13d,%esi
  418927:	mov    %r15,%rdi
  41892a:	callq  417953 <finddiff>
  41892f:	mov    %eax,%ebx
  418931:	mov    $0x61fe30,%esi
  418936:	mov    (%rsp),%rdi
  41893a:	callq  417ac6 <putcode>
  41893f:	mov    %ebp,%eax
  418941:	add    %r13d,%eax
  418944:	je     418968 <Fax3Encode2DRow+0x1f5>
  418946:	mov    %ebp,%eax
  418948:	sar    $0x3,%eax
  41894b:	cltq   
  41894d:	movzbl (%r15,%rax,1),%eax
  418952:	mov    %ebp,%ecx
  418954:	not    %ecx
  418956:	and    $0x7,%ecx
  418959:	sar    %cl,%eax
  41895b:	and    $0x1,%eax
  41895e:	cmp    %eax,0xc(%rsp)
  418962:	jne    4187fe <Fax3Encode2DRow+0x8b>
  418968:	mov    %r13d,%esi
  41896b:	sub    %ebp,%esi
  41896d:	mov    $0x641ee0,%edx
  418972:	mov    (%rsp),%rbp
  418976:	mov    %rbp,%rdi
  418979:	callq  417adb <putspan>
  41897e:	mov    %ebx,%esi
  418980:	sub    %r13d,%esi
  418983:	mov    $0x641c40,%edx
  418988:	mov    %rbp,%rdi
  41898b:	callq  417adb <putspan>
  418990:	mov    %ebx,%ebp
  418992:	jmpq   418848 <Fax3Encode2DRow+0xd5>
  418997:	mov    $0x61fe2a,%esi
  41899c:	mov    (%rsp),%rdi
  4189a0:	callq  417ac6 <putcode>
  4189a5:	mov    0x8(%rsp),%ebp
  4189a9:	jmpq   418848 <Fax3Encode2DRow+0xd5>
  4189ae:	mov    $0x1,%eax
  4189b3:	add    $0x18,%rsp
  4189b7:	pop    %rbx
  4189b8:	pop    %rbp
  4189b9:	pop    %r12
  4189bb:	pop    %r13
  4189bd:	pop    %r14
  4189bf:	pop    %r15
  4189c1:	retq   

00000000004189c2 <Fax3Encode>:
  4189c2:	push   %r13
  4189c4:	push   %r12
  4189c6:	push   %rbp
  4189c7:	push   %rbx
  4189c8:	sub    $0x8,%rsp
  4189cc:	mov    %rdi,%r12
  4189cf:	mov    %rsi,%rbp
  4189d2:	mov    %edx,%r13d
  4189d5:	mov    0x288(%rdi),%rbx
  4189dc:	test   %edx,%edx
  4189de:	jg     418a31 <Fax3Encode+0x6f>
  4189e0:	mov    $0x1,%eax
  4189e5:	jmpq   418a95 <Fax3Encode+0xd3>
  4189ea:	mov    0x28(%rbx),%rdx
  4189ee:	mov    0x10(%rbx),%ecx
  4189f1:	mov    %rbp,%rsi
  4189f4:	mov    %r12,%rdi
  4189f7:	callq  418773 <Fax3Encode2DRow>
  4189fc:	test   %eax,%eax
  4189fe:	je     418a95 <Fax3Encode+0xd3>
  418a04:	subw   $0x1,0x40(%rbx)
  418a09:	cmpw   $0x0,0x40(%rbx)
  418a0e:	jne    418a65 <Fax3Encode+0xa3>
  418a10:	movl   $0x0,0x18(%rbx)
  418a17:	movzwl 0x42(%rbx),%eax
  418a1b:	sub    $0x1,%eax
  418a1e:	mov    %ax,0x40(%rbx)
  418a22:	mov    0x8(%rbx),%rax
  418a26:	add    %rax,%rbp
  418a29:	sub    %eax,%r13d
  418a2c:	test   %r13d,%r13d
  418a2f:	jle    418a90 <Fax3Encode+0xce>
  418a31:	mov    %r12,%rdi
  418a34:	callq  4186c7 <Fax3PutEOL>
  418a39:	testb  $0x1,0xa8(%r12)
  418a42:	je     418a7c <Fax3Encode+0xba>
  418a44:	cmpl   $0x0,0x18(%rbx)
  418a48:	jne    4189ea <Fax3Encode+0x28>
  418a4a:	mov    0x10(%rbx),%edx
  418a4d:	mov    %rbp,%rsi
  418a50:	mov    %r12,%rdi
  418a53:	callq  417b87 <Fax3Encode1DRow>
  418a58:	test   %eax,%eax
  418a5a:	je     418a95 <Fax3Encode+0xd3>
  418a5c:	movl   $0x1,0x18(%rbx)
  418a63:	jmp    418a09 <Fax3Encode+0x47>
  418a65:	mov    0x8(%rbx),%rdx
  418a69:	mov    0x28(%rbx),%rsi
  418a6d:	mov    %rbp,%rdi
  418a70:	mov    $0x0,%eax
  418a75:	callq  4012d0 <bcopy@plt>
  418a7a:	jmp    418a22 <Fax3Encode+0x60>
  418a7c:	mov    0x10(%rbx),%edx
  418a7f:	mov    %rbp,%rsi
  418a82:	mov    %r12,%rdi
  418a85:	callq  417b87 <Fax3Encode1DRow>
  418a8a:	test   %eax,%eax
  418a8c:	jne    418a22 <Fax3Encode+0x60>
  418a8e:	jmp    418a95 <Fax3Encode+0xd3>
  418a90:	mov    $0x1,%eax
  418a95:	add    $0x8,%rsp
  418a99:	pop    %rbx
  418a9a:	pop    %rbp
  418a9b:	pop    %r12
  418a9d:	pop    %r13
  418a9f:	retq   

0000000000418aa0 <Fax4PostEncode>:
  418aa0:	push   %rbp
  418aa1:	push   %rbx
  418aa2:	sub    $0x8,%rsp
  418aa6:	mov    %rdi,%rbx
  418aa9:	mov    0x288(%rdi),%rbp
  418ab0:	callq  4186c7 <Fax3PutEOL>
  418ab5:	mov    %rbx,%rdi
  418ab8:	callq  4186c7 <Fax3PutEOL>
  418abd:	cmpw   $0x8,0x2(%rbp)
  418ac2:	je     418b09 <Fax4PostEncode+0x69>
  418ac4:	mov    0x2a0(%rbx),%rax
  418acb:	cmp    %rax,0x2b0(%rbx)
  418ad2:	jge    418b15 <Fax4PostEncode+0x75>
  418ad4:	movswq 0x0(%rbp),%rax
  418ad9:	mov    0x20(%rbp),%rdx
  418add:	movzbl (%rdx,%rax,1),%edx
  418ae1:	mov    0x2a8(%rbx),%rax
  418ae8:	lea    0x1(%rax),%rcx
  418aec:	mov    %rcx,0x2a8(%rbx)
  418af3:	mov    %dl,(%rax)
  418af5:	addq   $0x1,0x2b0(%rbx)
  418afd:	movw   $0x0,0x0(%rbp)
  418b03:	movw   $0x8,0x2(%rbp)
  418b09:	mov    $0x1,%eax
  418b0e:	add    $0x8,%rsp
  418b12:	pop    %rbx
  418b13:	pop    %rbp
  418b14:	retq   
  418b15:	mov    %rbx,%rdi
  418b18:	mov    $0x0,%eax
  418b1d:	callq  41425a <TIFFFlushData1>
  418b22:	jmp    418ad4 <Fax4PostEncode+0x34>

0000000000418b24 <Fax4Encode>:
  418b24:	push   %r13
  418b26:	push   %r12
  418b28:	push   %rbp
  418b29:	push   %rbx
  418b2a:	sub    $0x8,%rsp
  418b2e:	mov    %rdi,%r13
  418b31:	mov    %rsi,%rbp
  418b34:	mov    %edx,%r12d
  418b37:	mov    0x288(%rdi),%rbx
  418b3e:	test   %edx,%edx
  418b40:	jle    418b8c <Fax4Encode+0x68>
  418b42:	mov    0x28(%rbx),%rdx
  418b46:	mov    0x10(%rbx),%ecx
  418b49:	mov    %rbp,%rsi
  418b4c:	mov    %r13,%rdi
  418b4f:	callq  418773 <Fax3Encode2DRow>
  418b54:	test   %eax,%eax
  418b56:	je     418b81 <Fax4Encode+0x5d>
  418b58:	mov    0x8(%rbx),%rdx
  418b5c:	mov    0x28(%rbx),%rsi
  418b60:	mov    %rbp,%rdi
  418b63:	mov    $0x0,%eax
  418b68:	callq  4012d0 <bcopy@plt>
  418b6d:	mov    0x8(%rbx),%rax
  418b71:	add    %rax,%rbp
  418b74:	sub    %eax,%r12d
  418b77:	test   %r12d,%r12d
  418b7a:	jg     418b42 <Fax4Encode+0x1e>
  418b7c:	mov    $0x1,%eax
  418b81:	add    $0x8,%rsp
  418b85:	pop    %rbx
  418b86:	pop    %rbp
  418b87:	pop    %r12
  418b89:	pop    %r13
  418b8b:	retq   
  418b8c:	mov    $0x1,%eax
  418b91:	jmp    418b81 <Fax4Encode+0x5d>

0000000000418b93 <Fax4Decode>:
  418b93:	push   %r13
  418b95:	push   %r12
  418b97:	push   %rbp
  418b98:	push   %rbx
  418b99:	sub    $0x8,%rsp
  418b9d:	mov    %rdi,%r13
  418ba0:	mov    %rsi,%rbx
  418ba3:	mov    %edx,%r12d
  418ba6:	mov    0x288(%rdi),%rbp
  418bad:	mov    %edx,%esi
  418baf:	mov    %rbx,%rdi
  418bb2:	mov    $0x0,%eax
  418bb7:	callq  4012f0 <bzero@plt>
  418bbc:	test   %r12d,%r12d
  418bbf:	jle    418c07 <Fax4Decode+0x74>
  418bc1:	mov    0x10(%rbp),%edx
  418bc4:	mov    %rbx,%rsi
  418bc7:	mov    %r13,%rdi
  418bca:	callq  417ff6 <Fax3Decode2DRow>
  418bcf:	test   %eax,%eax
  418bd1:	je     418bfc <Fax4Decode+0x69>
  418bd3:	mov    0x8(%rbp),%rdx
  418bd7:	mov    0x28(%rbp),%rsi
  418bdb:	mov    %rbx,%rdi
  418bde:	mov    $0x0,%eax
  418be3:	callq  4012d0 <bcopy@plt>
  418be8:	mov    0x8(%rbp),%rax
  418bec:	add    %rax,%rbx
  418bef:	sub    %eax,%r12d
  418bf2:	test   %r12d,%r12d
  418bf5:	jg     418bc1 <Fax4Decode+0x2e>
  418bf7:	mov    $0x1,%eax
  418bfc:	add    $0x8,%rsp
  418c00:	pop    %rbx
  418c01:	pop    %rbp
  418c02:	pop    %r12
  418c04:	pop    %r13
  418c06:	retq   
  418c07:	mov    $0x1,%eax
  418c0c:	jmp    418bfc <Fax4Decode+0x69>

0000000000418c0e <TIFFInitCCITTFax4>:
  418c0e:	push   %rbx
  418c0f:	mov    %rdi,%rbx
  418c12:	mov    $0x0,%eax
  418c17:	callq  417f5e <TIFFInitCCITTFax3>
  418c1c:	movq   $0x418b93,0x240(%rbx)
  418c27:	movq   $0x418b93,0x250(%rbx)
  418c32:	movq   $0x418b93,0x260(%rbx)
  418c3d:	movq   $0x418b24,0x248(%rbx)
  418c48:	movq   $0x418b24,0x258(%rbx)
  418c53:	movq   $0x418b24,0x268(%rbx)
  418c5e:	movq   $0x418aa0,0x238(%rbx)
  418c69:	movb   $0x3,0xd(%rbx)
  418c6d:	mov    $0x1,%eax
  418c72:	pop    %rbx
  418c73:	retq   

0000000000418c74 <TIFFInitCCITTRLE>:
  418c74:	push   %rbx
  418c75:	mov    %rdi,%rbx
  418c78:	mov    $0x0,%eax
  418c7d:	callq  417f5e <TIFFInitCCITTFax3>
  418c82:	movq   $0x0,0x230(%rbx)
  418c8d:	movq   $0x0,0x238(%rbx)
  418c98:	movq   $0x414333,0x248(%rbx)
  418ca3:	movq   $0x41434b,0x258(%rbx)
  418cae:	movq   $0x414363,0x268(%rbx)
  418cb9:	movq   $0x0,0x270(%rbx)
  418cc4:	orb    $0x6,0xd(%rbx)
  418cc8:	mov    $0x1,%eax
  418ccd:	pop    %rbx
  418cce:	retq   

0000000000418ccf <TIFFInitCCITTRLEW>:
  418ccf:	push   %rbx
  418cd0:	mov    %rdi,%rbx
  418cd3:	mov    $0x0,%eax
  418cd8:	callq  417f5e <TIFFInitCCITTFax3>
  418cdd:	movq   $0x0,0x230(%rbx)
  418ce8:	movq   $0x0,0x238(%rbx)
  418cf3:	movq   $0x414333,0x248(%rbx)
  418cfe:	movq   $0x41434b,0x258(%rbx)
  418d09:	movq   $0x414363,0x268(%rbx)
  418d14:	movq   $0x0,0x270(%rbx)
  418d1f:	orb    $0xa,0xd(%rbx)
  418d23:	mov    $0x1,%eax
  418d28:	pop    %rbx
  418d29:	retq   
  418d2a:	nopw   0x0(%rax,%rax,1)

0000000000418d30 <__libc_csu_init>:
  418d30:	push   %r15
  418d32:	push   %r14
  418d34:	mov    %rdx,%r15
  418d37:	push   %r13
  418d39:	push   %r12
  418d3b:	lea    0x20609e(%rip),%r12        # 61ede0 <__frame_dummy_init_array_entry>
  418d42:	push   %rbp
  418d43:	lea    0x20609e(%rip),%rbp        # 61ede8 <__init_array_end>
  418d4a:	push   %rbx
  418d4b:	mov    %edi,%r13d
  418d4e:	mov    %rsi,%r14
  418d51:	sub    %r12,%rbp
  418d54:	sub    $0x8,%rsp
  418d58:	sar    $0x3,%rbp
  418d5c:	callq  401088 <_init>
  418d61:	test   %rbp,%rbp
  418d64:	je     418d86 <__libc_csu_init+0x56>
  418d66:	xor    %ebx,%ebx
  418d68:	nopl   0x0(%rax,%rax,1)
  418d70:	mov    %r15,%rdx
  418d73:	mov    %r14,%rsi
  418d76:	mov    %r13d,%edi
  418d79:	callq  *(%r12,%rbx,8)
  418d7d:	add    $0x1,%rbx
  418d81:	cmp    %rbx,%rbp
  418d84:	jne    418d70 <__libc_csu_init+0x40>
  418d86:	add    $0x8,%rsp
  418d8a:	pop    %rbx
  418d8b:	pop    %rbp
  418d8c:	pop    %r12
  418d8e:	pop    %r13
  418d90:	pop    %r14
  418d92:	pop    %r15
  418d94:	retq   
  418d95:	nop
  418d96:	nopw   %cs:0x0(%rax,%rax,1)

0000000000418da0 <__libc_csu_fini>:
  418da0:	repz retq 

Disassembly of section .fini:

0000000000418da4 <_fini>:
  418da4:	sub    $0x8,%rsp
  418da8:	add    $0x8,%rsp
  418dac:	retq   
