```
class Debugger {
public:
    Domain& attach(DomID domid);
    void detach();

private:
    XenCtrl _xenctrl; // etc
    std::optional<Domain> _domain;
}

class Domain() {

    // Roughly as it exists currently: a wrapper around the Xen interfaces

}
```
