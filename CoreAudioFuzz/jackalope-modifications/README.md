# Build instructions

```
git clone https://github.com/googleprojectzero/Jackalope.git
cd Jackalope
git clone --recurse-submodules https://github.com/googleprojectzero/TinyInst.git
cd ..
mkdir build
cd build
cmake -G Xcode ..
cmake --build . --config Release
```
