#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define p 17
#define q 14

#define FP_ONE          (int64_t)(1 << q)

#define INT_TO_FP(n)    ((int64_t)(n)*(FP_ONE))
#define FP_TO_INT(x)    (((x)>=0) ? (((x)+(FP_ONE)/2)/(FP_ONE)) : (((x)-(FP_ONE)/2)/(FP_ONE)))

#define MULT_X_Y(x,y)   (((x))*(y)/(FP_ONE))
#define DIV_X_Y(x,y)    (((x))*(FP_ONE)/(y))


#endif