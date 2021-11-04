void Compute_Pyramid_Level(level)
     long level;
{
  long outx,outy,outz;	/* Loop indices in image space               */
  long inx,iny,inz;
  long inx_plus_one,iny_plus_one,inz_plus_one;
  BOOLEAN bit;

  printf("      Computing pyramid level %ld from level %ld...\n",
	 level,level-1);
  for (outz=0; outz<pyr_len[level][Z]; outz++) {
    inz = outz<<1;
    inz_plus_one = MIN(inz+1,pyr_len[level-1][Z]-1);
    for (outy=0; outy<pyr_len[level][Y]; outy++) {
      iny = outy<<1;
      iny_plus_one = MIN(iny+1,pyr_len[level-1][Y]-1);
      for (outx=0; outx<pyr_len[level][X]; outx++) {
	inx = outx<<1;
	inx_plus_one = MIN(inx+1,pyr_len[level-1][X]-1);

	bit = PYR(level-1,inz,iny,inx);
	bit |= PYR(level-1,inz,iny,inx_plus_one);
	bit |= PYR(level-1,inz,iny_plus_one,inx);
	bit |= PYR(level-1,inz,iny_plus_one,inx_plus_one);
	bit |= PYR(level-1,inz_plus_one,iny,inx);
	bit |= PYR(level-1,inz_plus_one,iny,inx_plus_one);
	bit |= PYR(level-1,inz_plus_one,iny_plus_one,inx);
	bit |= PYR(level-1,inz_plus_one,iny_plus_one,inx_plus_one);

	WRITE_PYR(bit,level,outz,outy,outx);
      }
    }
  }
}

