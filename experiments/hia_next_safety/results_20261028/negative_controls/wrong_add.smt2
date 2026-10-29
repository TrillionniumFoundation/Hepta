(declare-fun a1 () (_ BitVec 32))
(declare-fun a0 () (_ BitVec 32))
(assert (let ((a!1 (distinct false (or false (and true (distinct 0 0)))))
      (a!2 (distinct (or (and true (= 0 0))) (or true))))
  (or false
      a!1
      a!2
      (and (and true (= 0 0)) true (distinct (bvadd a0 a1) (bvsub a0 a1))))))

(check-sat)
