%global debug_package %{nil}
%define kernel_version %(ver=`rpm -qa|grep kernel-devel`;echo ${ver#*kernel-devel-})

Name         :  dim_kernel
Summary      :  Dynamic Integrity Measurement
Version      :  1.0.1
Release      :  1
License      :  GPLV2
Source0      :  %{name}-v%{version}.tar.gz
BuildRequires:  kernel-devel kernel-headers
Requires     :  kernel

%description
Dynamic Integrity Measurement

%prep
%setup -n %{name}-v%{version}

%build
cd src
make

%install
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{kernel_version}/extra/dim
install -m 400 ./src/dim_core.ko $RPM_BUILD_ROOT/lib/modules/%{kernel_version}/extra/dim
install -m 400 ./src/dim_monitor.ko $RPM_BUILD_ROOT/lib/modules/%{kernel_version}/extra/dim

%pre

%post
depmod -a `uname -r`

%preun

%postun
depmod -a

%posttrans

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%attr(0400,root,root) /lib/modules/%{kernel_version}/extra/dim/dim_core.ko
%attr(0400,root,root) /lib/modules/%{kernel_version}/extra/dim/dim_monitor.ko

%changelog
