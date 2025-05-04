#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define p 17
#define q 14
#define f (1<<q)

#define CONVERT_N_TO_FIXED_POINT(n)             ((n)*(f))
#define CONVERT_X_TO_INTEGER_ZERO(x)            ((x)/(f))
#define CONVERT_X_TO_INTEGER_NEAREST(x)         (((x)>=0)?(((x)+(f)/2)/(f)):(((x)-(f)/2)/(f)))

#define ADD_X_AND_Y(x,y)                        ((x)+(y))
#define SUBTRACT_Y_FROM_X(x,y)                  ((x)-(y))
#define ADD_X_AND_N(x,n)                        ((x)+(n)*(f))
#define SUBTRACT_N_FROM_X(x,n)                  ((x)-(n)*(f))
#define MULTIPLY_X_BY_Y(x,y)                    (((int64_t) (x))*(y)/(f))
#define MULTIPLY_X_BY_N(x,n)                    ((x)*(n))
#define DIVIDE_X_BY_Y(x,y)                      (((int64_t) (x))*(f)/(y))
#define DIVIDE_X_BY_N(x,n)                      ((x)/(n))


#define FP_ONE (1 << q)

#define INT_TO_FP(n) (n * FP_ONE)
#define FP_TO_INT(x) (((x)>=0) ? (((x)+(FP_ONE)/2) / (FP_ONE) ) : (((x)-(FP_ONE)/2) / (FP_ONE)))

#define ADD_X_N(x, n) (x + n * FP_ONE)
#define SUB_X_N(x, n) (x - n * FP_ONE)
#define MULT_X_Y(x, y) (x * y / FP_ONE)
#define DIV_X_Y(x, y) (x * FP_ONE / y)




#endif