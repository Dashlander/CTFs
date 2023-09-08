; ModuleID = 'f.c'
source_filename = "f.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@__const.main.hex_str = private unnamed_addr constant [43 x i8] c"546869732069732061207465737420737472696e67\00", align 16
@.str = private unnamed_addr constant [55 x i8] c"4861636b527573684354467b315f6834355f363176336e5f75707d\00", align 1
@.str.1 = private unnamed_addr constant [28 x i8] c"The ciphered string is: %s\0A\00", align 1
@.str.2 = private unnamed_addr constant [5 x i8] c"%02x\00", align 1

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca [43 x i8], align 16
  %3 = alloca [256 x i8], align 16
  %4 = alloca [256 x i8], align 16
  %5 = alloca ptr, align 8
  store i32 0, ptr %1, align 4
  call void @llvm.memcpy.p0.p0.i64(ptr align 16 %2, ptr align 16 @__const.main.hex_str, i64 43, i1 false)
  store ptr @.str, ptr %5, align 8
  %6 = getelementptr inbounds [43 x i8], ptr %2, i64 0, i64 0
  %7 = getelementptr inbounds [256 x i8], ptr %3, i64 0, i64 0
  call void @hex_to_ascii(ptr noundef %6, ptr noundef %7)
  %8 = getelementptr inbounds [256 x i8], ptr %3, i64 0, i64 0
  %9 = load ptr, ptr %5, align 8
  call void @xor_cipher(ptr noundef %8, ptr noundef %9)
  %10 = getelementptr inbounds [256 x i8], ptr %3, i64 0, i64 0
  %11 = getelementptr inbounds [256 x i8], ptr %4, i64 0, i64 0
  call void @ascii_to_hex(ptr noundef %10, ptr noundef %11)
  %12 = getelementptr inbounds [256 x i8], ptr %4, i64 0, i64 0
  %13 = call i32 (ptr, ...) @printf(ptr noundef @.str.1, ptr noundef %12)
  ret i32 0
}

; Function Attrs: argmemonly nocallback nofree nounwind willreturn
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #1

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @hex_to_ascii(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  %8 = alloca i32, align 4
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  store i32 0, ptr %5, align 4
  store i32 0, ptr %6, align 4
  br label %9

9:                                                ; preds = %82, %2
  %10 = load ptr, ptr %3, align 8
  %11 = load i32, ptr %5, align 4
  %12 = sext i32 %11 to i64
  %13 = getelementptr inbounds i8, ptr %10, i64 %12
  %14 = load i8, ptr %13, align 1
  %15 = sext i8 %14 to i32
  %16 = icmp ne i32 %15, 0
  br i1 %16, label %17, label %87

17:                                               ; preds = %9
  %18 = load ptr, ptr %3, align 8
  %19 = load i32, ptr %5, align 4
  %20 = sext i32 %19 to i64
  %21 = getelementptr inbounds i8, ptr %18, i64 %20
  %22 = load i8, ptr %21, align 1
  %23 = sext i8 %22 to i32
  %24 = icmp sge i32 %23, 97
  br i1 %24, label %25, label %34

25:                                               ; preds = %17
  %26 = load ptr, ptr %3, align 8
  %27 = load i32, ptr %5, align 4
  %28 = sext i32 %27 to i64
  %29 = getelementptr inbounds i8, ptr %26, i64 %28
  %30 = load i8, ptr %29, align 1
  %31 = sext i8 %30 to i32
  %32 = sub nsw i32 %31, 97
  %33 = add nsw i32 %32, 10
  br label %42

34:                                               ; preds = %17
  %35 = load ptr, ptr %3, align 8
  %36 = load i32, ptr %5, align 4
  %37 = sext i32 %36 to i64
  %38 = getelementptr inbounds i8, ptr %35, i64 %37
  %39 = load i8, ptr %38, align 1
  %40 = sext i8 %39 to i32
  %41 = sub nsw i32 %40, 48
  br label %42

42:                                               ; preds = %34, %25
  %43 = phi i32 [ %33, %25 ], [ %41, %34 ]
  store i32 %43, ptr %7, align 4
  %44 = load ptr, ptr %3, align 8
  %45 = load i32, ptr %5, align 4
  %46 = add nsw i32 %45, 1
  %47 = sext i32 %46 to i64
  %48 = getelementptr inbounds i8, ptr %44, i64 %47
  %49 = load i8, ptr %48, align 1
  %50 = sext i8 %49 to i32
  %51 = icmp sge i32 %50, 97
  br i1 %51, label %52, label %62

52:                                               ; preds = %42
  %53 = load ptr, ptr %3, align 8
  %54 = load i32, ptr %5, align 4
  %55 = add nsw i32 %54, 1
  %56 = sext i32 %55 to i64
  %57 = getelementptr inbounds i8, ptr %53, i64 %56
  %58 = load i8, ptr %57, align 1
  %59 = sext i8 %58 to i32
  %60 = sub nsw i32 %59, 97
  %61 = add nsw i32 %60, 10
  br label %71

62:                                               ; preds = %42
  %63 = load ptr, ptr %3, align 8
  %64 = load i32, ptr %5, align 4
  %65 = add nsw i32 %64, 1
  %66 = sext i32 %65 to i64
  %67 = getelementptr inbounds i8, ptr %63, i64 %66
  %68 = load i8, ptr %67, align 1
  %69 = sext i8 %68 to i32
  %70 = sub nsw i32 %69, 48
  br label %71

71:                                               ; preds = %62, %52
  %72 = phi i32 [ %61, %52 ], [ %70, %62 ]
  store i32 %72, ptr %8, align 4
  %73 = load i32, ptr %7, align 4
  %74 = shl i32 %73, 4
  %75 = load i32, ptr %8, align 4
  %76 = add nsw i32 %74, %75
  %77 = trunc i32 %76 to i8
  %78 = load ptr, ptr %4, align 8
  %79 = load i32, ptr %6, align 4
  %80 = sext i32 %79 to i64
  %81 = getelementptr inbounds i8, ptr %78, i64 %80
  store i8 %77, ptr %81, align 1
  br label %82

82:                                               ; preds = %71
  %83 = load i32, ptr %5, align 4
  %84 = add nsw i32 %83, 2
  store i32 %84, ptr %5, align 4
  %85 = load i32, ptr %6, align 4
  %86 = add nsw i32 %85, 1
  store i32 %86, ptr %6, align 4
  br label %9, !llvm.loop !6

87:                                               ; preds = %9
  %88 = load ptr, ptr %4, align 8
  %89 = load i32, ptr %6, align 4
  %90 = sext i32 %89 to i64
  %91 = getelementptr inbounds i8, ptr %88, i64 %90
  store i8 0, ptr %91, align 1
  ret void
}

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @xor_cipher(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  store i32 0, ptr %5, align 4
  br label %6

6:                                                ; preds = %32, %2
  %7 = load ptr, ptr %3, align 8
  %8 = load i32, ptr %5, align 4
  %9 = sext i32 %8 to i64
  %10 = getelementptr inbounds i8, ptr %7, i64 %9
  %11 = load i8, ptr %10, align 1
  %12 = sext i8 %11 to i32
  %13 = icmp ne i32 %12, 0
  br i1 %13, label %14, label %35

14:                                               ; preds = %6
  %15 = load ptr, ptr %4, align 8
  %16 = load i32, ptr %5, align 4
  %17 = sext i32 %16 to i64
  %18 = load ptr, ptr %4, align 8
  %19 = call i64 @strlen(ptr noundef %18) #5
  %20 = urem i64 %17, %19
  %21 = getelementptr inbounds i8, ptr %15, i64 %20
  %22 = load i8, ptr %21, align 1
  %23 = sext i8 %22 to i32
  %24 = load ptr, ptr %3, align 8
  %25 = load i32, ptr %5, align 4
  %26 = sext i32 %25 to i64
  %27 = getelementptr inbounds i8, ptr %24, i64 %26
  %28 = load i8, ptr %27, align 1
  %29 = sext i8 %28 to i32
  %30 = xor i32 %29, %23
  %31 = trunc i32 %30 to i8
  store i8 %31, ptr %27, align 1
  br label %32

32:                                               ; preds = %14
  %33 = load i32, ptr %5, align 4
  %34 = add nsw i32 %33, 1
  store i32 %34, ptr %5, align 4
  br label %6, !llvm.loop !8

35:                                               ; preds = %6
  ret void
}

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @ascii_to_hex(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  store i32 0, ptr %5, align 4
  br label %6

6:                                                ; preds = %27, %2
  %7 = load ptr, ptr %3, align 8
  %8 = load i32, ptr %5, align 4
  %9 = sext i32 %8 to i64
  %10 = getelementptr inbounds i8, ptr %7, i64 %9
  %11 = load i8, ptr %10, align 1
  %12 = sext i8 %11 to i32
  %13 = icmp ne i32 %12, 0
  br i1 %13, label %14, label %30

14:                                               ; preds = %6
  %15 = load ptr, ptr %4, align 8
  %16 = load i32, ptr %5, align 4
  %17 = mul nsw i32 %16, 2
  %18 = sext i32 %17 to i64
  %19 = getelementptr inbounds i8, ptr %15, i64 %18
  %20 = load ptr, ptr %3, align 8
  %21 = load i32, ptr %5, align 4
  %22 = sext i32 %21 to i64
  %23 = getelementptr inbounds i8, ptr %20, i64 %22
  %24 = load i8, ptr %23, align 1
  %25 = sext i8 %24 to i32
  %26 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %19, ptr noundef @.str.2, i32 noundef %25) #6
  br label %27

27:                                               ; preds = %14
  %28 = load i32, ptr %5, align 4
  %29 = add nsw i32 %28, 1
  store i32 %29, ptr %5, align 4
  br label %6, !llvm.loop !9

30:                                               ; preds = %6
  %31 = load ptr, ptr %4, align 8
  %32 = load i32, ptr %5, align 4
  %33 = mul nsw i32 %32, 2
  %34 = sext i32 %33 to i64
  %35 = getelementptr inbounds i8, ptr %31, i64 %34
  store i8 0, ptr %35, align 1
  ret void
}

declare i32 @printf(ptr noundef, ...) #2

; Function Attrs: nounwind readonly willreturn
declare i64 @strlen(ptr noundef) #3

; Function Attrs: nounwind
declare i32 @sprintf(ptr noundef, ptr noundef, ...) #4

attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { argmemonly nocallback nofree nounwind willreturn }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind readonly willreturn "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { nounwind readonly willreturn }
attributes #6 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 15.0.7"}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
!8 = distinct !{!8, !7}
!9 = distinct !{!9, !7}
