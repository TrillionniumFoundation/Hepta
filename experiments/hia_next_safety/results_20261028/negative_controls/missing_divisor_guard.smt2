(declare-fun a1 () (_ BitVec 32))
(declare-fun a0 () (_ BitVec 32))
(assert (let ((a!1 (or false (and true (not (= a1 a1)))))
      (a!2 (ite (= 0 0) (ite (= a1 #x00000000) 2 0) 0)))
(let ((a!3 (distinct a!1 (or false (and true (distinct a!2 0)))))
      (a!4 (distinct (or (and true (= a!2 0))) (or (and true (= a1 a1))))))
  (or false
      (and (and true (= a1 a1)) (= a1 #x00000000))
      a!3
      a!4
      (and (and true (= a!2 0))
           (and true (= a1 a1))
           (distinct (bvudiv a0 a1) (bvudiv a0 a1)))))))

(check-sat)
