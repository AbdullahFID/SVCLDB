// ddup.cpp -- DXGI Desktop Duplication one-frame capturer (non-admin).
// This is THE modern screen-recording path (OBS/Teams/etc). It consumes
// dwmcore's CChannel::SyncDesktopCaptureBits -> CaptureBitsResponse::
// RenderForCapture -> CDrawingContext::DrawVisualTree -> CVisual/CWindowNode
// ::RenderContent (which svcldb hooks). If svcldb's capture-stealth covers
// this path, the overlay must be ABSENT from the captured frame even while
// it's visibly rendering on the physical display.
//
// Forces B8G8R8A8_UNORM via DuplicateOutput1 so an HDR (R10G10B10A2) desktop
// is converted to 8-bit for us. Writes a top-down 32bpp BMP.
//
//   cl /nologo /EHsc ddup.cpp /link d3d11.lib dxgi.lib
//   ddup.exe out.bmp
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_5.h>
#include <cstdio>
#include <cstdint>
#pragma comment(lib,"d3d11.lib")
#pragma comment(lib,"dxgi.lib")

static inline uint8_t clamp8f(float v){ if(v<=0.f)return 0; if(v>=1.f)return 255; return (uint8_t)(v*255.f+0.5f); }
static inline float halfToFloat(uint16_t h){
    uint32_t sign=(h>>15)&1u, exp=(h>>10)&0x1Fu, man=h&0x3FFu, f;
    if(exp==0){ if(man==0){ f=sign<<31; } else { int e=127-15+1; while(!(man&0x400u)){man<<=1;e--;} man&=0x3FFu; f=(sign<<31)|((uint32_t)e<<23)|(man<<13);} }
    else if(exp==0x1F){ f=(sign<<31)|(0xFFu<<23)|(man<<13); }
    else { f=(sign<<31)|((exp-15+127)<<23)|(man<<13); }
    float out; memcpy(&out,&f,4); return out;
}
// Convert a source frame (any of the common desktop formats) to a top-down 32bpp BGRA BMP.
static void writeBMP(const char* path,int w,int h,const uint8_t* src,int rowPitch,DXGI_FORMAT fmt){
    BITMAPFILEHEADER bfh; ZeroMemory(&bfh,sizeof(bfh));
    BITMAPINFOHEADER bih; ZeroMemory(&bih,sizeof(bih));
    int imgSize=w*h*4;
    bfh.bfType=0x4D42; bfh.bfOffBits=sizeof(bfh)+sizeof(bih); bfh.bfSize=bfh.bfOffBits+imgSize;
    bih.biSize=sizeof(bih); bih.biWidth=w; bih.biHeight=-h; bih.biPlanes=1; bih.biBitCount=32; bih.biCompression=BI_RGB;
    FILE* f=fopen(path,"wb"); if(!f){printf("fopen fail\n");return;}
    fwrite(&bfh,sizeof(bfh),1,f); fwrite(&bih,sizeof(bih),1,f);
    uint8_t* row=(uint8_t*)malloc((size_t)w*4);
    for(int y=0;y<h;y++){
        const uint8_t* s=src+(size_t)y*rowPitch;
        for(int x=0;x<w;x++){
            uint8_t b,g,r;
            if(fmt==DXGI_FORMAT_R16G16B16A16_FLOAT){ const uint16_t* p=(const uint16_t*)(s+(size_t)x*8); r=clamp8f(halfToFloat(p[0])); g=clamp8f(halfToFloat(p[1])); b=clamp8f(halfToFloat(p[2])); }
            else if(fmt==DXGI_FORMAT_R10G10B10A2_UNORM){ uint32_t v=*(const uint32_t*)(s+(size_t)x*4); r=(uint8_t)(((v)&0x3FF)>>2); g=(uint8_t)(((v>>10)&0x3FF)>>2); b=(uint8_t)(((v>>20)&0x3FF)>>2); }
            else if(fmt==DXGI_FORMAT_R8G8B8A8_UNORM){ const uint8_t* p=s+(size_t)x*4; r=p[0]; g=p[1]; b=p[2]; }
            else { const uint8_t* p=s+(size_t)x*4; b=p[0]; g=p[1]; r=p[2]; } // B8G8R8A8 / default
            uint8_t* o=row+(size_t)x*4; o[0]=b; o[1]=g; o[2]=r; o[3]=255;
        }
        fwrite(row,4,w,f);
    }
    free(row);
    fclose(f);
}

int main(int argc,char**argv){
    const char* out=argc>1?argv[1]:"ddup.bmp";
    int skip=argc>2?atoi(argv[2]):15;
    HRESULT hr;
    ID3D11Device* dev=nullptr; ID3D11DeviceContext* ctx=nullptr; D3D_FEATURE_LEVEL fl;
    hr=D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,0,nullptr,0,D3D11_SDK_VERSION,&dev,&fl,&ctx);
    if(FAILED(hr)){printf("D3D11CreateDevice=0x%08lx\n",(unsigned long)hr);return 1;}
    IDXGIDevice* dxgiDev=nullptr; dev->QueryInterface(__uuidof(IDXGIDevice),(void**)&dxgiDev);
    IDXGIAdapter* adapter=nullptr; dxgiDev->GetAdapter(&adapter);
    IDXGIOutput* output=nullptr; hr=adapter->EnumOutputs(0,&output);
    if(FAILED(hr)){printf("EnumOutputs=0x%08lx\n",(unsigned long)hr);return 2;}
    IDXGIOutput1* out1=nullptr; hr=output->QueryInterface(__uuidof(IDXGIOutput1),(void**)&out1);
    if(FAILED(hr)){printf("QI IDXGIOutput1=0x%08lx\n",(unsigned long)hr);return 3;}
    IDXGIOutputDuplication* dup=nullptr;
    hr=out1->DuplicateOutput(dev,&dup);   // accept native desktop format (HDR FP16 etc.)
    if(FAILED(hr)){printf("DuplicateOutput=0x%08lx\n",(unsigned long)hr);return 4;}
    IDXGIResource* res=nullptr; DXGI_OUTDUPL_FRAME_INFO fi;
    int got=0;
    for(int i=0;i<400;i++){
        if(res){res->Release();res=nullptr;}
        hr=dup->AcquireNextFrame(500,&fi,&res);
        if(hr==DXGI_ERROR_WAIT_TIMEOUT){Sleep(15);continue;}
        if(FAILED(hr)){printf("AcquireNextFrame=0x%08lx\n",(unsigned long)hr);return 5;}
        got++;
        if(got<skip){ dup->ReleaseFrame(); Sleep(15); continue; }
        break; // keep this frame (do NOT ReleaseFrame yet)
    }
    if(!res){printf("no frame acquired (screen static?)\n");return 6;}
    ID3D11Texture2D* acquired=nullptr; res->QueryInterface(__uuidof(ID3D11Texture2D),(void**)&acquired);
    D3D11_TEXTURE2D_DESC desc; acquired->GetDesc(&desc);
    D3D11_TEXTURE2D_DESC sd=desc; sd.Usage=D3D11_USAGE_STAGING; sd.BindFlags=0; sd.CPUAccessFlags=D3D11_CPU_ACCESS_READ; sd.MiscFlags=0;
    ID3D11Texture2D* stage=nullptr; hr=dev->CreateTexture2D(&sd,nullptr,&stage);
    if(FAILED(hr)){printf("CreateTexture2D=0x%08lx\n",(unsigned long)hr);return 7;}
    ctx->CopyResource(stage,acquired);
    D3D11_MAPPED_SUBRESOURCE map; hr=ctx->Map(stage,0,D3D11_MAP_READ,0,&map);
    if(FAILED(hr)){printf("Map=0x%08lx\n",(unsigned long)hr);return 8;}
    writeBMP(out,desc.Width,desc.Height,(const uint8_t*)map.pData,map.RowPitch,desc.Format);
    ctx->Unmap(stage,0);
    printf("OK %ux%u fmt=%u frames=%d -> %s\n",desc.Width,desc.Height,(unsigned)desc.Format,got,out);
    return 0;
}
