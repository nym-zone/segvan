FROM gcc:7
RUN git clone https://github.com/nym-zone/segvan && \
  cd segvan && \
  make
ENV PATH /segvan:$PATH