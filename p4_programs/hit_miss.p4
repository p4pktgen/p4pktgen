parser start {
    return ingress;
}

action a11() { }
action a12() { }

action a21() { }
action a22() { }

action a31() { }

action a41() { }
action a42() { }
action a43() { }

action a51() { }

action a61() { }

table t1 {
    actions { a11; a12; }
}

table t2 {
    actions { a21; a22; }
}

table t3 {
    actions { a31; }
}

table t4 {
    actions { a41; a42; a43; }
}

table t5 {
    actions { a51; }
}

table t6 {
    actions { a61; }
}

control ingress {
    apply(t1) {
        hit {
            apply(t2) {
                a21 {
                    apply(t3);
                }
                a22 {
                }
            }
        }
        miss {
            apply(t4) {
                a41 {
                    apply(t5);
                }
            }
        }
    }
    apply(t6);
}
