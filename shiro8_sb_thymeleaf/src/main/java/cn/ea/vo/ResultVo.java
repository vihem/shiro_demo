package cn.ea.vo;

public class ResultVo {
    private Object id;
    private String name;
    private Object value;
    private boolean flag;

    public ResultVo(Object id, String name, Object value) {
        this.id = id;
        this.name = name;
        this.value = value;
    }

    public ResultVo(Object id, String name, Object value, boolean flag) {
        this.id = id;
        this.name = name;
        this.value = value;
        this.flag = flag;
    }

    public Object getId() {
        return id;
    }

    public void setId(Object id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public boolean isFlag() {
        return flag;
    }

    public void setFlag(boolean flag) {
        this.flag = flag;
    }
}
