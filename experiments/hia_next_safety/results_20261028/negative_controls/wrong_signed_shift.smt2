(declare-fun a1 () (_ BitVec 32))
(declare-fun a0 () (_ BitVec 32))
(assert (let ((a!1 (or false (and true (not (bvult a1 #x00000020)))))
      (a!2 (ite (= 0 0) (ite (bvuge a1 #x00000020) 1 0) 0)))
(let ((a!3 (distinct a!1 (or false (and true (distinct a!2 0)))))
      (a!4 (distinct (or (and true (= a!2 0)))
                     (or (and true (bvult a1 #x00000020))))))
  (or false
      (and (and true (bvult a1 #x00000020)) (bvuge a1 #x00000020))
      a!3
      a!4
      (and (and true (= a!2 0))
           (and true (bvult a1 #x00000020))
           (distinct (bvashr a0 a1) (bvlshr a0 a1)))))))

(check-sat)
