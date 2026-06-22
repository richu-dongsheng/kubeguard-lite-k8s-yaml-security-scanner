import streamlit as st

st.set_page_config(
    page_title = "kubeguard-Lite",
    page_icon = "🛡️",
    layout = "wide",
)

st.title("kubeguard-Lite")
st.subheader("kubernetes YAML 静态配置安全扫描工具")

upload_file = st.file_uploader("上传 Kubernetes YAML 文件", type=["yaml", "yml"])

if upload_file is not None:
    content = upload_file.read().decode("utf-8")
    st.code(content,language="yaml")
    st.success("YAML 文件上传成功！后续将在这里接入扫描逻辑")