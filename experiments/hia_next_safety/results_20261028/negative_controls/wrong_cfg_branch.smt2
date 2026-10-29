(declare-fun a0 () (_ BitVec 32))
(declare-fun a1 () (_ BitVec 32))
(assert (let ((a!1 (and (and true (= 0 0)) (not (bvult a0 a1))))
      (a!2 (and (and (and true (= 0 0)) (bvult a0 a1)) (distinct 0 0)))
      (a!3 (and (and (and true (= 0 0)) (bvult a0 a1)) (= 0 0)))
      (a!6 (or (and true (not (bvugt a0 a1))) (and true (bvugt a0 a1)))))
(let ((a!4 (or false
               (and true (distinct 0 0))
               (and a!1 (distinct 0 0))
               (and (and a!1 (= 0 0)) (distinct 0 0))
               a!2
               (and a!3 (distinct 0 0))))
      (a!5 (or (and (and a!1 (= 0 0)) (= 0 0)) (and a!3 (= 0 0))))
      (a!7 (and (and (and a!1 (= 0 0)) (= 0 0))
                (and true (not (bvugt a0 a1)))
                (distinct a1 a1)))
      (a!8 (and (and (and a!1 (= 0 0)) (= 0 0))
                (and true (bvugt a0 a1))
                (distinct a1 a0)))
      (a!9 (and (and a!3 (= 0 0))
                (and true (not (bvugt a0 a1)))
                (distinct a0 a1))))
  (or false
      (distinct false a!4)
      (distinct a!5 a!6)
      a!7
      a!8
      a!9
      (and (and a!3 (= 0 0)) (and true (bvugt a0 a1)) (distinct a0 a0))))))

(check-sat)
